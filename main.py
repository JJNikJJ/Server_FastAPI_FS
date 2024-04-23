from fastapi import FastAPI, Form, Depends, HTTPException, Query
from jwt import PyJWTError
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from starlette.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from fastapi.responses import JSONResponse
import jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, Depends, HTTPException
import logging
from sqlalchemy import ForeignKey
from pydantic import BaseModel, EmailStr, constr
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
import jwt  # Импорт PyJWT
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
from jwt import PyJWTError, decode as jwt_decode

SECRET_KEY = "x8v9%Yp6w2!z@C4b#m3S5vQfR7q$W1uH"
ALGORITHM = "HS256"

# Настройка базы данных
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Определение модели пользователя
from sqlalchemy import String, Column


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    surname = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    phone = Column(String, index=True)
    password = Column(String)
    token = Column(String, index=True, nullable=True)  # Добавляем новое поле для токена
    orders = relationship("Order", back_populates="owner")


class Order(Base):
    __tablename__ = 'orders'
    id = Column(Integer, primary_key=True, index=True)
    origin_city = Column(String, index=True)
    origin_address = Column(String, index=True)
    destination_city = Column(String, index=True)
    destination_address = Column(String, index=True)
    estimated_time = Column(Float)
    remaining_distance = Column(Float)
    user_id = Column(Integer, ForeignKey('users.id'))
    owner = relationship("User", back_populates="orders")


Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Можно указать список доверенных доменов вместо "*", чтобы ограничить доступ
    allow_credentials=True,
    allow_methods=["*"],  # Можно изменить список методов по вашему выбору
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        # Декодирование токена с использованием SECRET_KEY и ALGORITHM
        payload = jwt_decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")  # Получаем идентификатор пользователя из токена
        if user_id is None:
            raise credentials_exception
        # Получение пользователя по user_id из базы данных
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise credentials_exception
    except PyJWTError as e:
        # Выводим ошибку декодирования для отладки
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"JWT decode exception: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        ) from e
    return user


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=60)  # Токен истекает через 60 минут
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


class UserSchema(BaseModel):
    id: int
    name: str
    surname: str
    email: str
    phone: str

    class Config:
        from_attributes = True


class RegistrationModel(BaseModel):
    phone: str
    email: str
    name: str
    surname: str
    password: constr(min_length=8)


class OrderCreate(BaseModel):
    origin_city: str
    origin_address: str
    destination_city: str
    destination_address: str
    estimated_time: float
    remaining_distance: float
    user_id: int


class OrderBase(BaseModel):
    order_number: str
    origin_address: str
    destination_address: str
    remaining_time: float

    class Config:
        from_attributes = True


class OrderModel(BaseModel):
    id: int
    estimated_time: int
    origin_address: str
    destination_address: str
    status: str
    total_cost: float

    class Config:
        from_attributes = True


class OrderResponse(BaseModel):
    id: int
    origin_city: str
    origin_address: str
    destination_city: str
    destination_address: str
    estimated_time: float
    remaining_distance: float
    total_cost: float  # Убедитесь, что это поле получает значение
    status: str

def create_order(db: Session, order: OrderCreate):
    db_order = Order(**order.dict())
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return db_order


# Использование этой модели в эндпоинте регистрации
@app.post("/register/")
async def register_user(request: Request, user_data: RegistrationModel, db: Session = Depends(get_db)):
    logging.info(f"Received data: {await request.json()}")

    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        logging.error("Email already registered")
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user_data.password)
    user = User(
        phone=user_data.phone,
        email=user_data.email,
        name=user_data.name,
        surname=user_data.surname,
        password=hashed_password
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Генерация токена
    access_token = create_access_token(data={"sub": user.id})
    user.token = access_token  # Сохранение токена в базе данных
    db.commit()

    response_data = {
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "name": user.name,
        "surname": user.surname
    }
    logging.info(f"Response data: {response_data}")
    return JSONResponse(status_code=200, content=response_data)


class AuthModel(BaseModel):
    phone: str
    password: str


# Использование этой модели в эндпоинте аутентификации
@app.post("/auth/")
async def authenticate_user(user_data: AuthModel, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.phone == user_data.phone).first()
    if user and verify_password(user_data.password, user.password):
        access_token = create_access_token(data={"sub": user.phone})
        return JSONResponse(status_code=200, content={
            "status": "success",
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user.id,
            "name": user.name,
            "surname": user.surname,
            "message": "Authentication successful"
        })
    else:
        return JSONResponse(status_code=401, content={"detail": "Invalid phone number or password"})


# Эндпоинт для получения данных текущего пользователя
@app.get("/users/me", response_model=UserSchema)
async def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/orders/")
async def create_order(order_data: OrderCreate, db: Session = Depends(get_db)):
    print(order_data)  # Выводит данные в консоль сервера
    # Предполагаем, что OrderCreate - это Pydantic модель, описывающая структуру данных
    new_order = Order(
        origin_city=order_data.origin_city,
        origin_address=order_data.origin_address,
        destination_city=order_data.destination_city,
        destination_address=order_data.destination_address,
        estimated_time=order_data.estimated_time,
        remaining_distance=order_data.remaining_distance,
        user_id=order_data.user_id  # Убедитесь, что это поле существует в модели
    )
    db.add(new_order)
    db.commit()
    db.refresh(new_order)
    return {"status": "success", "message": "Order created successfully"}


@app.get("/orders_list/")
async def read_orders(user_id: int, db: Session = Depends(get_db)):
    orders = db.query(Order).filter(Order.user_id == user_id).all()
    if not orders:
        raise HTTPException(status_code=404, detail="Orders not found")
    return orders


@app.get("/orders_detail/{order_id}")
def get_order_detail(order_id: int, db: Session = Depends(get_db)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order