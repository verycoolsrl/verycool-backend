from fastapi import FastAPI, APIRouter, HTTPException, Depends
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, validator
from typing import List, Optional
from datetime import datetime
from bson import ObjectId
from passlib.context import CryptContext

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'verycool_db')]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Create the main app without a prefix
app = FastAPI(title="VeryCool API", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Admin secret code - from environment
ADMIN_SECRET_CODE = os.environ.get('ADMIN_SECRET_CODE', 'VeryCool2025')

# ==================== MODELS ====================

class PyObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return str(v)

class UserBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    phone: str = Field(..., pattern=r'^[0-9]{10}$')
    
class UserCreate(UserBase):
    password: str = Field(..., min_length=6)
    role: str = Field(default="client")
    admin_code: Optional[str] = None
    referral_code: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    name: str
    email: str
    phone: str
    role: str
    status: str = "pending"  # pending, active, inactive
    stickers: int = 0
    referral_code: str
    referred_by: Optional[str] = None
    referrals_count: int = 0
    has_first_wash: bool = False
    first_wash_discount: int = 10
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}

class Appointment(BaseModel):
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    client_id: str
    client_name: str
    client_email: str
    client_phone: str
    service_type: str
    vehicle_type: str
    location: str
    appointment_date: datetime
    status: str = "scheduled"  # scheduled, completed, cancelled, no_show
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}

class AppointmentCreate(BaseModel):
    service_type: str
    vehicle_type: str
    location: str
    appointment_date: datetime
    notes: Optional[str] = None

class NotificationCreate(BaseModel):
    target_type: str = Field(..., pattern=r'^(all|single)$')
    client_id: Optional[str] = None
    message: str = Field(..., min_length=1)
    notification_type: str = Field(default="message")  # "message" or "discount"
    discount_percentage: Optional[int] = None

# ==================== HELPER FUNCTIONS ====================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    try:
        return pwd_context.hash(password)
    except Exception as e:
        print(f"Password hash error: {e}")
        raise HTTPException(status_code=500, detail=f"Password hashing failed: {str(e)}")

def generate_referral_code(name: str) -> str:
    """Generate a unique referral code from user name"""
    import random
    import string
    base = name.upper().replace(" ", "")[:6]
    random_part = ''.join(random.choices(string.digits, k=4))
    return f"{base}{random_part}"

async def check_admin_exists():
    """Check if any admin already exists"""
    admin = await db.users.find_one({"role": "admin"})
    return admin is not None

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    """Register a new user (client or admin)"""
    
    # Check if email already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # If registering as admin
    if user_data.role == "admin":
        # Check if an admin already exists
        admin_exists = await check_admin_exists()
        if admin_exists:
            raise HTTPException(status_code=403, detail="Admin registration is closed. Contact existing admin.")
        
        # Verify admin code
        if user_data.admin_code != ADMIN_SECRET_CODE:
            raise HTTPException(status_code=400, detail="Invalid admin code")
        
        status = "active"
    else:
        # Client registration - status is pending
        status = "pending"
    
    # Hash password
    hashed_password = get_password_hash(user_data.password)
    
    # Generate referral code for clients
    referral_code = generate_referral_code(user_data.name) if user_data.role == "client" else ""
    
    # Handle referral if provided
    referred_by = None
    if user_data.referral_code and user_data.role == "client":
        referrer = await db.users.find_one({"referral_code": user_data.referral_code, "role": "client"})
        if referrer:
            referred_by = str(referrer["_id"])
            # Update referrer's referral count
            await db.users.update_one(
                {"_id": referrer["_id"]},
                {"$inc": {"referrals_count": 1}}
            )
    
    # Create user
    user = {
        "name": user_data.name,
        "email": user_data.email,
        "phone": user_data.phone,
        "password": hashed_password,
        "role": user_data.role,
        "status": status,
        "stickers": 0,
        "referral_code": referral_code,
        "referred_by": referred_by,
        "referrals_count": 0,
        "has_first_wash": False,
        "first_wash_discount": 10 if user_data.role == "client" else 0,
        "created_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user)
    user["_id"] = str(result.inserted_id)
    
    return {
        "success": True,
        "message": "Admin account created!" if user_data.role == "admin" else "Account created! Waiting for admin approval.",
        "user": {
            "id": user["_id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "status": user["status"]
        }
    }

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    """Login user - finds by email only, role determined automatically"""

    # Find user by email only (no role needed)
    user = await db.users.find_one({"email": credentials.email})
    if not user:
        raise HTTPException(status_code=401, detail="Email sau parolă incorectă")

    # Verify password
    if not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Email sau parolă incorectă")

    # Return user data (excluding password)
    user["_id"] = str(user["_id"])
    user.pop("password", None)

    return {
        "success": True,
        "user": user
    }

@api_router.get("/auth/check-admin-exists")
async def check_admin_registration():
    """Check if admin registration is available"""
    admin_exists = await check_admin_exists()
    return {"admin_exists": admin_exists}

# ==================== CLIENT ROUTES ====================

@api_router.get("/clients")
async def get_clients(search: Optional[str] = None):
    """Get all clients (admin only)"""
    
    query = {"role": "client"}
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}},
            {"phone": {"$regex": search, "$options": "i"}}
        ]
    
    clients = await db.users.find(query).sort("created_at", -1).to_list(1000)
    
    for client in clients:
        client["_id"] = str(client["_id"])
        client.pop("password", None)
    
    return clients

@api_router.get("/clients/{client_id}")
async def get_client(client_id: str):
    """Get client details"""
    
    if not ObjectId.is_valid(client_id):
        raise HTTPException(status_code=400, detail="Invalid client ID")
    
    client = await db.users.find_one({"_id": ObjectId(client_id), "role": "client"})
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    client["_id"] = str(client["_id"])
    client.pop("password", None)
    
    # Get appointments count
    appointments_count = await db.appointments.count_documents({"client_id": client_id})
    client["appointments_count"] = appointments_count
    
    return client

@api_router.patch("/clients/{client_id}/activate")
async def activate_client(client_id: str):
    """Activate a client (admin only)"""
    
    if not ObjectId.is_valid(client_id):
        raise HTTPException(status_code=400, detail="Invalid client ID")
    
    result = await db.users.update_one(
        {"_id": ObjectId(client_id), "role": "client"},
        {"$set": {"status": "active"}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    
    return {"success": True, "message": "Client activated"}

@api_router.patch("/clients/{client_id}/deactivate")
async def deactivate_client(client_id: str):
    """Deactivate a client (admin only)"""
    
    if not ObjectId.is_valid(client_id):
        raise HTTPException(status_code=400, detail="Invalid client ID")
    
    result = await db.users.update_one(
        {"_id": ObjectId(client_id), "role": "client"},
        {"$set": {"status": "inactive"}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    
    return {"success": True, "message": "Client deactivated"}

@api_router.delete("/clients/{client_id}")
async def delete_client(client_id: str):
    """Delete a client (admin only)"""
    
    if not ObjectId.is_valid(client_id):
        raise HTTPException(status_code=400, detail="Invalid client ID")
    
    result = await db.users.delete_one({"_id": ObjectId(client_id), "role": "client"})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    
    # Delete client's appointments
    await db.appointments.delete_many({"client_id": client_id})
    
    return {"success": True, "message": "Client deleted"}

@api_router.patch("/clients/{client_id}/add-sticker")
async def add_sticker(client_id: str):
    """Add a sticker to client (admin only)"""
    
    if not ObjectId.is_valid(client_id):
        raise HTTPException(status_code=400, detail="Invalid client ID")
    
    client = await db.users.find_one({"_id": ObjectId(client_id), "role": "client"})
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    new_stickers = client.get("stickers", 0) + 1
    
    # Reset to 0 if reached 4 (or higher)
    if new_stickers >= 4:
        new_stickers = 0
    
    await db.users.update_one(
        {"_id": ObjectId(client_id)},
        {"$set": {"stickers": new_stickers}}
    )
    
    return {
        "success": True,
        "stickers": new_stickers,
        "free_wash_earned": new_stickers == 0
    }

# ==================== APPOINTMENT ROUTES ====================

@api_router.post("/appointments")
async def create_appointment(appointment: AppointmentCreate, client_id: str):
    """Create a new appointment"""
    
    if not ObjectId.is_valid(client_id):
        raise HTTPException(status_code=400, detail="Invalid client ID")
    
    # Get client details
    client = await db.users.find_one({"_id": ObjectId(client_id)})
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    # Create appointment
    appointment_doc = {
        "client_id": client_id,
        "client_name": client["name"],
        "client_email": client["email"],
        "client_phone": client["phone"],
        "service_type": appointment.service_type,
        "vehicle_type": appointment.vehicle_type,
        "location": appointment.location,
        "appointment_date": appointment.appointment_date,
        "status": "scheduled",
        "notes": appointment.notes,
        "created_at": datetime.utcnow()
    }
    
    result = await db.appointments.insert_one(appointment_doc)
    appointment_doc["_id"] = str(result.inserted_id)
    
    return {"success": True, "appointment": appointment_doc}

@api_router.get("/appointments")
async def get_appointments(client_id: Optional[str] = None):
    """Get appointments (all for admin, own for client)"""
    
    query = {}
    if client_id:
        if not ObjectId.is_valid(client_id):
            raise HTTPException(status_code=400, detail="Invalid client ID")
        query["client_id"] = client_id
    
    appointments = await db.appointments.find(query).sort("appointment_date", -1).to_list(1000)
    
    for appointment in appointments:
        appointment["_id"] = str(appointment["_id"])
    
    return appointments

@api_router.patch("/appointments/{appointment_id}/cancel")
async def cancel_appointment(appointment_id: str):
    """Cancel an appointment"""
    
    if not ObjectId.is_valid(appointment_id):
        raise HTTPException(status_code=400, detail="Invalid appointment ID")
    
    result = await db.appointments.update_one(
        {"_id": ObjectId(appointment_id)},
        {"$set": {"status": "cancelled"}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    return {"success": True, "message": "Appointment cancelled"}

@api_router.patch("/appointments/{appointment_id}/complete")
async def complete_appointment(appointment_id: str):
    """Mark appointment as completed (admin only)"""
    
    if not ObjectId.is_valid(appointment_id):
        raise HTTPException(status_code=400, detail="Invalid appointment ID")
    
    result = await db.appointments.update_one(
        {"_id": ObjectId(appointment_id)},
        {"$set": {"status": "completed"}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    return {"success": True, "message": "Appointment marked as completed"}

# ==================== ADMIN ROUTES ====================

@api_router.post("/admin/create")
async def create_admin_by_admin(admin_data: UserCreate):
    """Create a new admin (admin only)"""
    
    # Check if email already exists
    existing_user = await db.users.find_one({"email": admin_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    hashed_password = get_password_hash(admin_data.password)
    
    # Create admin
    user = {
        "name": admin_data.name,
        "email": admin_data.email,
        "phone": admin_data.phone,
        "password": hashed_password,
        "role": "admin",
        "status": "active",
        "stickers": 0,
        "referral_code": "",
        "referred_by": None,
        "referrals_count": 0,
        "has_first_wash": False,
        "first_wash_discount": 0,
        "created_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user)
    user["_id"] = str(result.inserted_id)
    user.pop("password", None)
    
    return {
        "success": True,
        "message": "Admin created successfully",
        "user": user
    }

@api_router.post("/admin/send-message")
async def send_message(data: NotificationCreate):
    """Send message to clients (admin only) - stores in DB"""

    if data.target_type == "single" and not data.client_id:
        raise HTTPException(status_code=400, detail="Client ID is required for single target")

    notification = {
        "target_type": data.target_type,
        "client_id": data.client_id if data.target_type == "single" else None,
        "message": data.message.strip(),
        "notification_type": "message",
        "discount_percentage": None,
        "read_by": [],
        "created_at": datetime.utcnow()
    }

    await db.notifications.insert_one(notification)

    if data.target_type == "all":
        count = await db.users.count_documents({"role": "client", "status": "active"})
        return {"success": True, "message": f"Mesaj trimis la {count} clienți", "count": count}
    else:
        client = await db.users.find_one({"_id": ObjectId(data.client_id), "role": "client"})
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        return {"success": True, "message": f"Mesaj trimis la {client['name']}", "count": 1}

@api_router.post("/admin/send-discount")
async def send_discount(data: NotificationCreate):
    """Send discount to clients (admin only) - stores in DB"""

    if data.target_type == "single" and not data.client_id:
        raise HTTPException(status_code=400, detail="Client ID is required for single target")

    notification = {
        "target_type": data.target_type,
        "client_id": data.client_id if data.target_type == "single" else None,
        "message": data.message.strip(),
        "notification_type": "discount",
        "discount_percentage": data.discount_percentage or 10,
        "read_by": [],
        "created_at": datetime.utcnow()
    }

    await db.notifications.insert_one(notification)

    if data.target_type == "all":
        count = await db.users.count_documents({"role": "client", "status": "active"})
        return {"success": True, "message": f"{data.discount_percentage}% discount trimis la {count} clienți", "count": count}
    else:
        client = await db.users.find_one({"_id": ObjectId(data.client_id), "role": "client"})
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        return {"success": True, "message": f"{data.discount_percentage}% discount trimis la {client['name']}", "count": 1}

@api_router.get("/notifications")
async def get_notifications(client_id: str):
    """Get notifications for a client (broadcasts + individual)"""

    if not ObjectId.is_valid(client_id):
        raise HTTPException(status_code=400, detail="Invalid client ID")

    # Get notifications targeted at this client OR broadcast to all
    notifications = await db.notifications.find({
        "$or": [
            {"target_type": "all"},
            {"client_id": client_id}
        ]
    }).sort("created_at", -1).to_list(100)

    for n in notifications:
        n["_id"] = str(n["_id"])
        n["is_read"] = client_id in n.get("read_by", [])

    return notifications

@api_router.patch("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, client_id: str):
    """Mark a notification as read by a client"""

    if not ObjectId.is_valid(notification_id):
        raise HTTPException(status_code=400, detail="Invalid notification ID")

    await db.notifications.update_one(
        {"_id": ObjectId(notification_id)},
        {"$addToSet": {"read_by": client_id}}
    )

    return {"success": True}

@api_router.get("/stats")
async def get_stats():
    """Get dashboard statistics (admin only)"""
    
    total_clients = await db.users.count_documents({"role": "client"})
    active_clients = await db.users.count_documents({"role": "client", "status": "active"})
    pending_clients = await db.users.count_documents({"role": "client", "status": "pending"})
    total_appointments = await db.appointments.count_documents({})
    completed_appointments = await db.appointments.count_documents({"status": "completed"})
    scheduled_appointments = await db.appointments.count_documents({"status": "scheduled"})
    
    return {
        "total_clients": total_clients,
        "active_clients": active_clients,
        "pending_clients": pending_clients,
        "total_appointments": total_appointments,
        "completed_appointments": completed_appointments,
        "scheduled_appointments": scheduled_appointments
    }

# ==================== ROOT ROUTES ====================

@api_router.get("/")
async def root():
    return {"message": "VeryCool API - Spălătorie Mobilă cu Abur 🚗💧"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
