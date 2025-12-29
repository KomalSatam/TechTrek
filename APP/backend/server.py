from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME')]

# JWT settings
JWT_SECRET = os.environ.get('JWT_SECRET', 'mindcircle_secret_key_12345')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 720  # 30 days

# LLM settings
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY', '')

app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# ==================== MODELS ====================

class UserSignup(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: str
    name: str
    coins: int = 0
    badges: List[str] = []
    mental_fitness_score: int = 0
    created_at: str

class MoodCheckin(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: str
    mood: str  # 😢, 😟, 😐, 🙂, 😊
    stress_level: int  # 1-5
    note: Optional[str] = None
    timestamp: str

class MoodCheckinCreate(BaseModel):
    mood: str
    stress_level: int
    note: Optional[str] = None

class Journal(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: str
    title: str
    content: str
    created_at: str

class JournalCreate(BaseModel):
    title: str
    content: str

class AIChatMessage(BaseModel):
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: str

class AIChatSession(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: str
    messages: List[AIChatMessage]
    created_at: str
    updated_at: str

class AIChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None

class CommunityPost(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: str
    author_name: str
    group: str  # Students, Working professionals, Teens, Women, Exam-stress
    content: str
    is_anonymous: bool = False
    reactions: List[str] = []  # Support sticker IDs
    created_at: str

class CommunityPostCreate(BaseModel):
    group: str
    content: str
    is_anonymous: bool = False

class CommunityReaction(BaseModel):
    post_id: str
    reaction: str  # heart, hug, strength, peace

class HealingExercise(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    type: str  # breathing, meditation, quiz
    title: str
    description: str
    duration_minutes: int
    audio_url: Optional[str] = None
    instructions: Optional[str] = None

class Meetup(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    host_id: str
    host_name: str
    title: str
    description: str
    scheduled_time: str
    meet_link: Optional[str] = None
    participants: List[str] = []
    created_at: str

class MeetupCreate(BaseModel):
    title: str
    description: str
    scheduled_time: str
    meet_link: Optional[str] = None

class EmergencyContact(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: str
    name: str
    phone: str
    relationship: str

class EmergencyContactCreate(BaseModel):
    name: str
    phone: str
    relationship: str

# ==================== AUTH HELPERS ====================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# ==================== AUTH ENDPOINTS ====================

@api_router.post("/auth/signup")
async def signup(user: UserSignup):
    existing = await db.users.find_one({"email": user.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    hashed_pwd = hash_password(user.password)
    
    user_doc = {
        "id": user_id,
        "email": user.email,
        "password": hashed_pwd,
        "name": user.name,
        "coins": 0,
        "badges": [],
        "mental_fitness_score": 0,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(user_doc)
    token = create_jwt_token(user_id, user.email)
    
    return {
        "token": token,
        "user": UserProfile(**{k: v for k, v in user_doc.items() if k != 'password'})
    }

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user_doc = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user_doc or not verify_password(credentials.password, user_doc['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(user_doc['id'], user_doc['email'])
    return {
        "token": token,
        "user": UserProfile(**{k: v for k, v in user_doc.items() if k != 'password'})
    }

@api_router.get("/auth/me", response_model=UserProfile)
async def get_me(user_id: str = Depends(get_current_user)):
    user_doc = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    return UserProfile(**user_doc)

# ==================== MOOD TRACKING ====================

@api_router.post("/mood/checkin", response_model=MoodCheckin)
async def create_mood_checkin(checkin: MoodCheckinCreate, user_id: str = Depends(get_current_user)):
    checkin_id = str(uuid.uuid4())
    checkin_doc = {
        "id": checkin_id,
        "user_id": user_id,
        "mood": checkin.mood,
        "stress_level": checkin.stress_level,
        "note": checkin.note,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    await db.mood_checkins.insert_one(checkin_doc)
    
    # Award coins
    await db.users.update_one({"id": user_id}, {"$inc": {"coins": 10, "mental_fitness_score": 5}})
    
    return MoodCheckin(**checkin_doc)

@api_router.get("/mood/history", response_model=List[MoodCheckin])
async def get_mood_history(user_id: str = Depends(get_current_user)):
    checkins = await db.mood_checkins.find({"user_id": user_id}, {"_id": 0}).sort("timestamp", -1).to_list(100)
    return [MoodCheckin(**c) for c in checkins]

@api_router.get("/mood/trends")
async def get_mood_trends(user_id: str = Depends(get_current_user)):
    checkins = await db.mood_checkins.find({"user_id": user_id}, {"_id": 0}).sort("timestamp", -1).to_list(30)
    
    if not checkins:
        return {"avg_stress": 0, "mood_distribution": {}, "trend": "neutral"}
    
    avg_stress = sum(c['stress_level'] for c in checkins) / len(checkins)
    mood_counts = {}
    for c in checkins:
        mood_counts[c['mood']] = mood_counts.get(c['mood'], 0) + 1
    
    # Check if user needs support
    recent_5 = checkins[:5]
    high_stress_count = sum(1 for c in recent_5 if c['stress_level'] >= 4)
    needs_support = high_stress_count >= 3
    
    return {
        "avg_stress": round(avg_stress, 2),
        "mood_distribution": mood_counts,
        "needs_support": needs_support,
        "total_checkins": len(checkins)
    }

# ==================== JOURNAL ====================

@api_router.post("/journal", response_model=Journal)
async def create_journal(journal: JournalCreate, user_id: str = Depends(get_current_user)):
    journal_id = str(uuid.uuid4())
    journal_doc = {
        "id": journal_id,
        "user_id": user_id,
        "title": journal.title,
        "content": journal.content,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.journals.insert_one(journal_doc)
    await db.users.update_one({"id": user_id}, {"$inc": {"coins": 5}})
    
    return Journal(**journal_doc)

@api_router.get("/journal", response_model=List[Journal])
async def get_journals(user_id: str = Depends(get_current_user)):
    journals = await db.journals.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return [Journal(**j) for j in journals]

@api_router.delete("/journal/{journal_id}")
async def delete_journal(journal_id: str, user_id: str = Depends(get_current_user)):
    result = await db.journals.delete_one({"id": journal_id, "user_id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Journal not found")
    return {"success": True}

# ==================== AI CHAT ====================

@api_router.post("/ai/chat")
async def ai_chat(request: AIChatRequest, user_id: str = Depends(get_current_user)):
    session_id = request.session_id or str(uuid.uuid4())
    
    # Get or create session
    session_doc = await db.ai_chat_sessions.find_one({"id": session_id, "user_id": user_id}, {"_id": 0})
    
    if not session_doc:
        session_doc = {
            "id": session_id,
            "user_id": user_id,
            "messages": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
    
    # Add user message
    user_message = {
        "role": "user",
        "content": request.message,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    session_doc['messages'].append(user_message)
    
    # Call LLM
    try:
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=session_id,
            system_message="You are a compassionate mental health support companion. Provide empathetic, supportive responses. Offer coping strategies, mindfulness tips, and encouragement. Never diagnose or replace professional help. Keep responses warm, understanding, and helpful."
        ).with_model("openai", "gpt-5.2")
        
        llm_message = UserMessage(text=request.message)
        ai_response = await chat.send_message(llm_message)
        
        assistant_message = {
            "role": "assistant",
            "content": ai_response,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        session_doc['messages'].append(assistant_message)
        
    except Exception as e:
        logging.error(f"LLM error: {str(e)}")
        assistant_message = {
            "role": "assistant",
            "content": "I'm here to support you. How are you feeling today?",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        session_doc['messages'].append(assistant_message)
    
    session_doc['updated_at'] = datetime.now(timezone.utc).isoformat()
    
    await db.ai_chat_sessions.replace_one(
        {"id": session_id, "user_id": user_id},
        session_doc,
        upsert=True
    )
    
    return {
        "session_id": session_id,
        "message": assistant_message,
        "all_messages": session_doc['messages']
    }

@api_router.get("/ai/sessions", response_model=List[AIChatSession])
async def get_ai_sessions(user_id: str = Depends(get_current_user)):
    sessions = await db.ai_chat_sessions.find({"user_id": user_id}, {"_id": 0}).sort("updated_at", -1).to_list(50)
    return [AIChatSession(**s) for s in sessions]

# ==================== COMMUNITY ====================

@api_router.post("/community/post", response_model=CommunityPost)
async def create_community_post(post: CommunityPostCreate, user_id: str = Depends(get_current_user)):
    user_doc = await db.users.find_one({"id": user_id}, {"_id": 0})
    
    post_id = str(uuid.uuid4())
    post_doc = {
        "id": post_id,
        "user_id": user_id,
        "author_name": "Anonymous" if post.is_anonymous else user_doc['name'],
        "group": post.group,
        "content": post.content,
        "is_anonymous": post.is_anonymous,
        "reactions": [],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.community_posts.insert_one(post_doc)
    await db.users.update_one({"id": user_id}, {"$inc": {"coins": 5}})
    
    return CommunityPost(**post_doc)

@api_router.get("/community/posts", response_model=List[CommunityPost])
async def get_community_posts(group: Optional[str] = None):
    query = {"group": group} if group else {}
    posts = await db.community_posts.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return [CommunityPost(**p) for p in posts]

@api_router.post("/community/react")
async def react_to_post(reaction: CommunityReaction, user_id: str = Depends(get_current_user)):
    result = await db.community_posts.update_one(
        {"id": reaction.post_id},
        {"$push": {"reactions": reaction.reaction}}
    )
    
    if result.modified_count > 0:
        await db.users.update_one({"id": user_id}, {"$inc": {"coins": 3, "mental_fitness_score": 2}})
    
    return {"success": True}

# ==================== SOS / EMERGENCY ====================

@api_router.post("/emergency/contacts", response_model=EmergencyContact)
async def add_emergency_contact(contact: EmergencyContactCreate, user_id: str = Depends(get_current_user)):
    contact_id = str(uuid.uuid4())
    contact_doc = {
        "id": contact_id,
        "user_id": user_id,
        "name": contact.name,
        "phone": contact.phone,
        "relationship": contact.relationship
    }
    
    await db.emergency_contacts.insert_one(contact_doc)
    return EmergencyContact(**contact_doc)

@api_router.get("/emergency/contacts", response_model=List[EmergencyContact])
async def get_emergency_contacts(user_id: str = Depends(get_current_user)):
    contacts = await db.emergency_contacts.find({"user_id": user_id}, {"_id": 0}).to_list(10)
    return [EmergencyContact(**c) for c in contacts]

@api_router.delete("/emergency/contacts/{contact_id}")
async def delete_emergency_contact(contact_id: str, user_id: str = Depends(get_current_user)):
    result = await db.emergency_contacts.delete_one({"id": contact_id, "user_id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Contact not found")
    return {"success": True}

@api_router.post("/emergency/sos")
async def trigger_sos(user_id: str = Depends(get_current_user)):
    # Log SOS event
    sos_doc = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.sos_events.insert_one(sos_doc)
    
    # In real app, send alerts to emergency contacts
    return {"success": True, "message": "Emergency contacts notified"}

# ==================== HEALING EXERCISES ====================

@api_router.get("/exercises", response_model=List[HealingExercise])
async def get_healing_exercises():
    exercises = await db.healing_exercises.find({}, {"_id": 0}).to_list(100)
    
    # Seed exercises if empty
    if not exercises:
        seed_exercises = [
            {
                "id": str(uuid.uuid4()),
                "type": "breathing",
                "title": "4-7-8 Breathing",
                "description": "A calming breathing technique to reduce anxiety",
                "duration_minutes": 5,
                "instructions": "Breathe in for 4 counts, hold for 7, exhale for 8. Repeat 4 times."
            },
            {
                "id": str(uuid.uuid4()),
                "type": "meditation",
                "title": "Body Scan Meditation",
                "description": "Mindful awareness of physical sensations",
                "duration_minutes": 10,
                "instructions": "Lie down comfortably. Focus attention on each body part, from toes to head."
            },
            {
                "id": str(uuid.uuid4()),
                "type": "breathing",
                "title": "Box Breathing",
                "description": "Used by Navy SEALs for stress management",
                "duration_minutes": 5,
                "instructions": "Breathe in 4 counts, hold 4, exhale 4, hold 4. Repeat."
            },
            {
                "id": str(uuid.uuid4()),
                "type": "meditation",
                "title": "Loving-Kindness Meditation",
                "description": "Cultivate compassion for self and others",
                "duration_minutes": 8,
                "instructions": "Repeat phrases: May I be happy, may I be healthy, may I be safe."
            },
            {
                "id": str(uuid.uuid4()),
                "type": "quiz",
                "title": "Self-Awareness Check",
                "description": "Quick reflection on your current state",
                "duration_minutes": 3,
                "instructions": "Answer: How am I feeling? What do I need? What am I grateful for?"
            }
        ]
        await db.healing_exercises.insert_many(seed_exercises)
        exercises = seed_exercises
    
    return [HealingExercise(**e) for e in exercises]

@api_router.post("/exercises/{exercise_id}/complete")
async def complete_exercise(exercise_id: str, user_id: str = Depends(get_current_user)):
    # Log completion
    completion_doc = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "exercise_id": exercise_id,
        "completed_at": datetime.now(timezone.utc).isoformat()
    }
    await db.exercise_completions.insert_one(completion_doc)
    
    # Award coins and score
    await db.users.update_one({"id": user_id}, {"$inc": {"coins": 15, "mental_fitness_score": 10}})
    
    return {"success": True, "coins_earned": 15}

# ==================== MEETUPS ====================

@api_router.post("/meetups", response_model=Meetup)
async def create_meetup(meetup: MeetupCreate, user_id: str = Depends(get_current_user)):
    user_doc = await db.users.find_one({"id": user_id}, {"_id": 0})
    
    meetup_id = str(uuid.uuid4())
    meetup_doc = {
        "id": meetup_id,
        "host_id": user_id,
        "host_name": user_doc['name'],
        "title": meetup.title,
        "description": meetup.description,
        "scheduled_time": meetup.scheduled_time,
        "meet_link": meetup.meet_link,
        "participants": [user_id],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.meetups.insert_one(meetup_doc)
    return Meetup(**meetup_doc)

@api_router.get("/meetups", response_model=List[Meetup])
async def get_meetups():
    meetups = await db.meetups.find({}, {"_id": 0}).sort("scheduled_time", 1).to_list(50)
    return [Meetup(**m) for m in meetups]

@api_router.post("/meetups/{meetup_id}/join")
async def join_meetup(meetup_id: str, user_id: str = Depends(get_current_user)):
    result = await db.meetups.update_one(
        {"id": meetup_id},
        {"$addToSet": {"participants": user_id}}
    )
    return {"success": result.modified_count > 0}

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()