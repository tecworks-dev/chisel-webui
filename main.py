from fastapi import FastAPI, HTTPException, Request, Depends, status, Response, Body
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, field_validator
from contextlib import asynccontextmanager
import json
import os
from termcolor import colored
import asyncio
import psutil
import typing as t
from pathlib import Path
import subprocess
import re
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional
import sys
import platform
import requests
import gzip
import shutil
import stat

# Constants
CONFIG_FILE = "config.json"
CHISEL_USERS_FILE = "users.json"  # For chisel authentication
WEB_USERS_FILE = "web_users.json"  # For web interface users
DEFAULT_PORT_RANGE = (3000, 9000)
DOCKER_COMPOSE_FILE = "docker-compose.yml"
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
WEB_PORT = 8000  # Web interface port
CHISEL_PORT = 8081  # Dedicated port for Chisel server

# Load server configuration
def load_server_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                print(colored("Successfully loaded server configuration", "green"))
                return config
        print(colored("Config file not found, using default configuration", "yellow"))
        return {
            "server_url": "127.0.0.1",
            "web_port": WEB_PORT,
            "chisel_port": CHISEL_PORT
        }
    except Exception as e:
        print(colored(f"Error loading server configuration: {str(e)}", "red"))
        return {
            "server_url": "127.0.0.1",
            "web_port": WEB_PORT,
            "chisel_port": CHISEL_PORT
        }

def save_server_config(config: dict):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
            print(colored("Successfully saved server configuration", "green"))
    except Exception as e:
        print(colored(f"Error saving server configuration: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail="Could not save server configuration")

# Load initial configuration
SERVER_CONFIG = load_server_config()
SERVER_IP = SERVER_CONFIG["server_url"]

# Security Constants
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")  # Change in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,  # Adjust the number of rounds for security/performance balance
    bcrypt__ident="2b"  # Use the latest bcrypt identifier
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Add these constants at the top with other constants
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"  # Change in production
DEFAULT_ADMIN_EMAIL = "admin@example.com"

print(colored(f"Templates directory: {TEMPLATES_DIR}", "cyan"))
print(colored(f"Static directory: {STATIC_DIR}", "cyan"))

def update_exposed_ports_with_correct_passwords():
    """Update all exposed ports to use correct passwords from users.json"""
    try:
        print(colored("Updating exposed ports with correct passwords...", "cyan"))
        # Get all users' data
        web_users = load_web_users()
        chisel_users = load_chisel_users()
        
        # Process each user's allowed ports
        for username, user_data in web_users.items():
            # Get user's password from chisel_users
            user_password = get_user_password_from_chisel_users(username)
            if not user_password:
                continue
                
            # Update allowed ports patterns if necessary
            if "allowed_ports" in user_data:
                print(colored(f"Processing allowed ports for user {username}", "cyan"))
                
                # Save updated web users
                save_web_users(web_users)
                print(colored(f"Successfully updated ports for user {username}", "green"))
                
        print(colored("Successfully updated all port configurations", "green"))
    except Exception as e:
        print(colored(f"Error updating port configurations: {str(e)}", "red"))

def check_port_available(port: int) -> bool:
    """Check if a port is available for use"""
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port and conn.status == 'LISTEN':
                return False
        return True
    except Exception as e:
        print(colored(f"Error checking port {port}: {str(e)}", "red"))
        return False

async def download_chisel():
    """Download the appropriate Chisel executable for the current platform"""
    try:
        print(colored("Checking for Chisel executable...", "cyan"))
        
        # Determine OS and architecture
        os_name = platform.system().lower()
        machine = platform.machine().lower()
        
        # Map OS names
        os_map = {
            "windows": "windows",
            "linux": "linux",
            "darwin": "darwin",
            "openbsd": "openbsd"
        }
        os_name = os_map.get(os_name, os_name)
        
        # Map architectures
        arch_map = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "i386": "386",
            "i686": "386",
            "aarch64": "arm64",
            "arm64": "arm64",
            "armv7l": "armv7",
            "armv6l": "armv6",
            "armv5l": "armv5",
            "ppc64le": "ppc64le",
            "ppc64": "ppc64",
            "s390x": "s390x",
            "mips": "mips",
            "mips64": "mips64"
        }
        arch = arch_map.get(machine, machine)
        
        if not os_name in os_map.values():
            raise Exception(f"Unsupported operating system: {os_name}")
        if not arch in arch_map.values():
            raise Exception(f"Unsupported architecture: {arch}")

        # Get current directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        chisel_exe = "chisel.exe" if os_name == "windows" else "chisel"
        chisel_path = os.path.join(current_dir, chisel_exe)

        # Check if Chisel already exists and is executable
        if os.path.exists(chisel_path):
            if os.access(chisel_path, os.X_OK):
                print(colored("Chisel executable already exists and is executable", "green"))
                return chisel_path
            else:
                print(colored("Chisel exists but is not executable, fixing permissions...", "yellow"))
                os.chmod(chisel_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                return chisel_path

        # Set version and construct download URL
        VERSION = "1.10.1"
        
        # Determine package format
        if os_name == "linux":
            # Check if we're on a system that supports deb/rpm/apk
            if os.path.exists("/etc/debian_version"):
                package_format = "deb"
            elif os.path.exists("/etc/redhat-release"):
                package_format = "rpm"
            elif os.path.exists("/etc/alpine-release"):
                package_format = "apk"
            else:
                package_format = "gz"  # Fallback to gz
        else:
            package_format = "gz"

        # Construct base filename
        base_filename = f"chisel_{VERSION}_{os_name}_{arch}"
        
        # Add package extension
        if package_format != "gz":
            download_url = f"https://github.com/jpillora/chisel/releases/download/v{VERSION}/{base_filename}.{package_format}"
        else:
            download_url = f"https://github.com/jpillora/chisel/releases/download/v{VERSION}/{base_filename}.gz"
        if os.name == "nt":
            package_format = "exe"
            download_url = "https://github.com/tecworks-dev/chisel-webui/raw/refs/heads/main/chisel.exe"
        
        print(colored(f"Downloading Chisel from: {download_url}", "cyan"))

        # Download file
        response = requests.get(download_url)
        response.raise_for_status()

        # Handle different package formats
        if package_format == "gz":
            # Save compressed file
            gz_path = os.path.join(current_dir, "chisel.gz")
            with open(gz_path, "wb") as f:
                f.write(response.content)

            # Extract
            print(colored("Extracting Chisel...", "cyan"))
            with gzip.open(gz_path, 'rb') as f_in:
                # Set the correct output filename based on OS
                output_filename = "chisel.exe" if os.name == "nt" else "chisel"
                output_path = os.path.join(current_dir, output_filename)
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Clean up
            os.remove(gz_path)
        else:
            # Save package file
            pkg_path = os.path.join(current_dir, f"chisel.{package_format}")
            with open(pkg_path, "wb") as f:
                f.write(response.content)

            # Install package using appropriate command
            print(colored(f"Installing {package_format} package...", "cyan"))
            try:
                if package_format == "deb":
                    subprocess.run(["dpkg", "-i", pkg_path], check=True)
                elif package_format == "rpm":
                    subprocess.run(["rpm", "-i", pkg_path], check=True)
                elif package_format == "apk":
                    subprocess.run(["apk", "add", "--allow-untrusted", pkg_path], check=True)
            finally:
                if os.name == "nt":
                    pass
                else:
                    # Clean up package file
                    os.remove(pkg_path)

        # Make executable
        print(colored("Setting executable permissions...", "cyan"))
        os.chmod(chisel_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

        print(colored("Chisel downloaded and configured successfully", "green"))
        return chisel_path

    except Exception as e:
        print(colored(f"Error downloading Chisel: {str(e)}", "red"))
        raise

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Check if Chisel port is available first
    """
    Manages the lifespan of the Chisel application, ensuring that
    necessary setup and cleanup tasks are performed.

    This function first checks if the designated Chisel port is
    available and exits if it is already in use. It then attempts to
    download the Chisel executable, migrate user data from
    `users.json` to `web_users.json` if necessary, and create a
    default admin user if no users are present.

    The function also checks for and terminates any existing Chisel
    processes, ensuring that the port remains available.

    Upon startup, it initiates the Chisel server process, using the
    appropriate authentication and port configuration. During
    shutdown, it terminates any running Chisel processes to ensure
    a clean exit.

    Args:
        app (FastAPI): The FastAPI application instance.

    Yields:
        None: Used as an async context manager within the FastAPI app.
    """

    if not check_port_available(CHISEL_PORT):
        print(colored(f"ERROR: Port {CHISEL_PORT} is already in use. Cannot start Chisel server.", "red"))
        print(colored("Please ensure no other Chisel instance is running and try again.", "yellow"))
        sys.exit(1)
        
    # Startup
    try:
        # Download Chisel executable
        chisel_path = await download_chisel()
        print(colored(f"Using Chisel executable at: {chisel_path}", "green"))

        print(colored("Running in local mode - not starting Docker container", "cyan"))
        
        # Check if web_users.json exists
        if not os.path.exists(WEB_USERS_FILE):
            print(colored("web_users.json not found, attempting to migrate from users.json", "yellow"))
            
            # Load users from users.json
            chisel_users = load_chisel_users()
            web_users = {}
            
            for auth_str, allowed_ports in chisel_users.items():
                try:
                    username, password = auth_str.split(':')
                    
                    # Create web user entry
                    web_user = {
                        "username": username,
                        "email": f"{username}@example.com",  # Default email
                        "full_name": username.title(),  # Capitalize username as full name
                        "role": "admin" if username == "admin" else "user",
                        "is_active": True,
                        "hashed_password": get_password_hash(password),
                        "created_at": datetime.now().isoformat(),
                        "last_login": None,
                        "allowed_ports": allowed_ports
                    }
                    
                    web_users[username] = web_user
                    print(colored(f"Migrated user: {username}", "green"))
                    
                except Exception as e:
                    print(colored(f"Error migrating user {auth_str}: {str(e)}", "red"))
                    continue
            
            # Save the migrated users
            save_web_users(web_users)
            print(colored("Successfully migrated users from users.json to web_users.json", "green"))
        
        # Create default admin user if no users exist
        web_users = load_web_users()
        if not web_users:
            print(colored("Creating default admin user...", "yellow"))
            default_admin = {
                "username": DEFAULT_ADMIN_USERNAME,
                "email": DEFAULT_ADMIN_EMAIL,
                "full_name": "System Administrator",
                "role": UserRole.ADMIN,
                "is_active": True,
                "hashed_password": get_password_hash(DEFAULT_ADMIN_PASSWORD),
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "allowed_ports": ["^0.0.0.0:[0-9]+$", "^R:0.0.0.0:[0-9]+$"]
            }
            web_users[DEFAULT_ADMIN_USERNAME] = default_admin
            save_web_users(web_users)
            
            # Also create chisel user for admin
            chisel_users = load_chisel_users()
            chisel_users[f"{DEFAULT_ADMIN_USERNAME}:{DEFAULT_ADMIN_PASSWORD}"] = ["^0.0.0.0:[0-9]+$", "^R:0.0.0.0:[0-9]+$"]
            save_chisel_users(chisel_users)
            
            print(colored(f"Default admin user created with username: {DEFAULT_ADMIN_USERNAME} and password: {DEFAULT_ADMIN_PASSWORD}", "green"))
            print(colored("IMPORTANT: Please change the default admin password!", "red"))

        # Update all exposed ports with correct passwords
        update_exposed_ports_with_correct_passwords()

        # Check if Chisel is running and start it if not
        print(colored("Checking Chisel server status...", "cyan"))
        chisel_running = False
        chisel_pid = None
        
        # Verify port is still available
        if not check_port_available(CHISEL_PORT):
            print(colored(f"ERROR: Port {CHISEL_PORT} is already in use. Cannot start Chisel server.", "red"))
            print(colored("Please ensure no other Chisel instance is running and try again.", "yellow"))
            sys.exit(1)
            
        try:
            # Check for existing Chisel processes
            for proc in psutil.process_iter(['pid', 'name']):
                if 'chisel' in proc.info['name'].lower():
                    try:
                        chisel_pid = proc.info['pid']
                        psutil.Process(chisel_pid).kill()
                        print(colored(f"Killed existing Chisel process with PID {chisel_pid}", "yellow"))
                        await asyncio.sleep(1)  # Wait for process to die
                    except psutil.NoSuchProcess:
                        pass
            
            # Verify port is available after killing processes
            if not check_port_available(CHISEL_PORT):
                print(colored(f"ERROR: Port {CHISEL_PORT} is still in use after killing Chisel processes.", "red"))
                print(colored("Please check for other processes using this port.", "yellow"))
                sys.exit(1)

            # Now check if any Chisel process is still running
            for proc in psutil.process_iter(['pid', 'name']):
                if 'chisel' in proc.info['name'].lower():
                    chisel_running = True
                    chisel_pid = proc.info['pid']
                    print(colored(f"Chisel server is already running with PID {chisel_pid}", "green"))
                    break
        except Exception as e:
            print(colored(f"Error checking Chisel processes: {str(e)}", "yellow"))

        if not chisel_running:
            print(colored("Chisel server not running, starting it now...", "yellow"))
            try:
                # Get the current directory and chisel executable path
                current_dir = os.path.dirname(os.path.abspath(__file__))
                chisel_exe = os.path.join(current_dir, "chisel.exe" if os.name == "nt" else "chisel")
                
                if not os.path.exists(chisel_exe):
                    print(colored(f"Error: Chisel executable not found at {chisel_exe}", "red"))
                    print(colored("Please make sure chisel.exe is in the same directory as main.py", "yellow"))
                else:
                    # Get absolute path to users.json
                    auth_file = os.path.join(current_dir, CHISEL_USERS_FILE)
                    
                    # Build command with proper path escaping
                    cmd = [
                        chisel_exe,
                        "server",
                        f"--authfile={auth_file}",
                        f"--port={CHISEL_PORT}"  # Use dedicated Chisel port
                    ]
                    print(colored(f"Chisel command: {' '.join(cmd)}", "cyan"))
                    # Use appropriate flags for Windows
                    is_windows = os.name == "nt"
                    
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if is_windows else 0,
                        cwd=current_dir  # Set working directory explicitly
                    )
                    
                    await asyncio.sleep(2)  # Wait for server to start
                    
                    # Check if process started successfully
                    if process.poll() is None:
                        print(colored(f"Chisel server started successfully on port {CHISEL_PORT}", "green"))
                    else:
                        stdout, stderr = process.communicate()
                        error_msg = f"Chisel failed to start at startup. stdout: {stdout.decode()}, stderr: {stderr.decode()}"
                        print(colored(error_msg, "red"))
            except Exception as e:
                print(colored(f"Error starting Chisel server at startup: {str(e)}", "red"))

    except Exception as e:
        print(colored(f"Error during startup: {str(e)}", "red"))

    yield
    
    # Shutdown - cleanup any running Chisel processes
    print(colored("Cleaning up Chisel processes...", "yellow"))
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if 'chisel' in proc.info['name'].lower():
                try:
                    psutil.Process(proc.info['pid']).kill()
                    print(colored(f"Killed Chisel process with PID {proc.info['pid']}", "yellow"))
                except psutil.NoSuchProcess:
                    pass
    except Exception as e:
        print(colored(f"Error during cleanup: {str(e)}", "red"))
    
    print(colored("Running in local mode - no Docker container to stop", "yellow"))

app = FastAPI(title="Chisel Control Panel", lifespan=lifespan)

# Ensure directories exist
os.makedirs(STATIC_DIR, exist_ok=True)

# Mount static files and templates
try:
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    print(colored("Successfully mounted static files", "green"))
except Exception as e:
    print(colored(f"Error mounting static files: {str(e)}", "red"))

try:
    templates = Jinja2Templates(directory=TEMPLATES_DIR)
    print(colored("Successfully initialized templates", "green"))
except Exception as e:
    print(colored(f"Error initializing templates: {str(e)}", "red"))

class UserRole:
    ADMIN = "admin"
    USER = "user"

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: str
    role: str = UserRole.USER
    allowed_ports: t.List[str] = []
    is_active: bool = True

    @field_validator('role')
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in [UserRole.ADMIN, UserRole.USER]:
            raise ValueError('Invalid role')
        return v

class UserCreate(UserBase):
    password: str

class UserInDB(UserBase):
    hashed_password: str
    created_at: datetime = datetime.now()
    last_login: Optional[datetime] = None

class User(UserBase):
    id: str
    created_at: datetime
    last_login: Optional[datetime]

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class PortExposure(BaseModel):
    local_port: int
    remote_port: int
    username: str
    description: str

class ServerConfig(BaseModel):
    server_url: str
    web_port: int = WEB_PORT
    chisel_port: int = CHISEL_PORT

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def load_web_users() -> dict:
    try:
        if os.path.exists(WEB_USERS_FILE):
            with open(WEB_USERS_FILE, "r", encoding="utf-8") as f:
                users_data = json.load(f)
                print(colored(f"Successfully loaded web users from {WEB_USERS_FILE}", "green"))
                return users_data
        print(colored(f"Web users file not found, creating new one", "yellow"))
        return {}
    except Exception as e:
        print(colored(f"Error loading web users: {str(e)}", "red"))
        return {}

def save_web_users(users_data: dict):
    try:
        with open(WEB_USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users_data, f, indent=2)
            print(colored("Successfully saved web users to file", "green"))
    except Exception as e:
        print(colored(f"Error saving web users: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail="Could not save web users")

def load_chisel_users() -> dict:
    try:
        if os.path.exists(CHISEL_USERS_FILE):
            with open(CHISEL_USERS_FILE, "r", encoding="utf-8") as f:
                users_data = json.load(f)
                print(colored(f"Successfully loaded chisel users from {CHISEL_USERS_FILE}", "green"))
                return users_data
        print(colored(f"Chisel users file not found, creating new one", "yellow"))
        return {}
    except Exception as e:
        print(colored(f"Error loading chisel users: {str(e)}", "red"))
        return {}

def save_chisel_users(users_data: dict):
    try:
        with open(CHISEL_USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users_data, f, indent=2)
            print(colored("Successfully saved chisel users to file", "green"))
    except Exception as e:
        print(colored(f"Error saving chisel users: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail="Could not save chisel users")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    web_users = load_web_users()
    user = web_users.get(token_data.username)
    if user is None:
        raise credentials_exception
    return UserInDB(**user)

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        print(colored(f"Login attempt for user: {form_data.username}", "cyan"))
        web_users = load_web_users()
        
        if form_data.username not in web_users:
            print(colored(f"User {form_data.username} not found", "red"))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user = web_users[form_data.username]
        print(colored("User found, verifying password: " + form_data.password + " hash: " + get_password_hash(form_data.password), "cyan"))
        
        if not verify_password(form_data.password, user["hashed_password"]):
            print(colored("Invalid password", "red"))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Update last login
        print(colored("Password verified, updating last login...", "green"))
        web_users[user["username"]]["last_login"] = datetime.now().isoformat()
        save_web_users(web_users)

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["username"]}, expires_delta=access_token_expires
        )
        print(colored(f"Login successful for user: {form_data.username}", "green"))
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        print(colored(f"Unexpected error during login: {str(e)}", "red"))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login"
        )

@app.post("/api/users", response_model=User)
async def create_user(user: UserCreate, current_user: UserInDB = Depends(get_current_active_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create new users"
        )

    web_users = load_web_users()
    
    
    if user.username in web_users:
        raise HTTPException(status_code=400, detail="Username already registered")
    if any(u["email"] == user.email for u in web_users.values()):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_dict = user.dict()
    user_dict["hashed_password"] = get_password_hash(user.password)
    user_dict["created_at"] = datetime.now().isoformat()
    del user_dict["password"]

    web_users[user.username] = user_dict
    save_web_users(web_users)

    # Also create chisel user
    chisel_users = load_chisel_users()
    chisel_users[f"{user.username}:{user.password}"] = []  # Empty list of allowed ports initially
    save_chisel_users(chisel_users)

    await restart_chisel_server()
    return User(**user_dict, id=user.username)

@app.get("/api/users/me", response_model=User)
async def read_users_me(current_user: UserInDB = Depends(get_current_active_user)):
    return User(**current_user.dict(), id=current_user.username)

@app.get("/api/users", response_model=t.List[User])
async def get_users(current_user: UserInDB = Depends(get_current_active_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can view all users"
        )
    users = load_web_users()
    return [User(**u, id=username) for username, u in users.items()]

@app.put("/api/users/{username}", response_model=User)
async def update_user(
    username: str,
    user_update: UserBase,
    current_user: UserInDB = Depends(get_current_active_user)
):
    if current_user.role != UserRole.ADMIN and current_user.username != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only update your own user info unless you're an admin"
        )

    users = load_web_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    # Preserve sensitive/unchangeable fields
    user_dict = user_update.dict()
    user_dict["hashed_password"] = users[username]["hashed_password"]
    user_dict["created_at"] = users[username]["created_at"]
    user_dict["last_login"] = users[username].get("last_login")

    users[username] = user_dict
    save_web_users(users)
    await restart_chisel_server()
    return User(**user_dict, id=username)

@app.delete("/api/users/{username}")
async def delete_user(
    username: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can delete users"
        )

    users = load_web_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    del users[username]
    save_web_users(users)
    await restart_chisel_server()
    return {"message": "User deleted successfully"}

@app.put("/api/users/{username}/password")
async def change_password(
    username: str,
    current_user: UserInDB = Depends(get_current_active_user),
    password_data: dict = Body(...)
):
    try:
        # Only allow users to change their own password, unless they're admin
        if current_user.role != UserRole.ADMIN and current_user.username != username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only change your own password unless you're an admin"
            )

        # Extract password data from request body
        old_password = password_data.get('old_password')
        new_password = password_data.get('new_password')

        if not old_password or not new_password:
            raise HTTPException(
                status_code=400,
                detail="Both old_password and new_password are required"
            )

        # Load users
        web_users = load_web_users()
        if username not in web_users:
            raise HTTPException(status_code=404, detail="User not found")

        # Verify old password (skip verification for admin override)
        if current_user.role != UserRole.ADMIN or old_password != 'admin_override':
            if not verify_password(old_password, web_users[username]["hashed_password"]):
                raise HTTPException(status_code=400, detail="Incorrect old password")

        # Update web_users.json with hashed password
        web_users[username]["hashed_password"] = get_password_hash(new_password)
        save_web_users(web_users)
        print(colored(f"Updated hashed password for user {username} in web_users.json", "green"))

        # # Update chisel users.json with plain text password
        # chisel_users = load_chisel_users()
        # old_auth_key = None
        # old_ports = None

        # # Find and store the old ports configuration
        # for auth_key, ports in chisel_users.items():
        #     if auth_key.startswith(f"{username}:"):
        #         old_auth_key = auth_key
        #         old_ports = ports.copy()
        #         break

        # if old_auth_key and old_ports:
        #     # Add new entry with new plain text password
        #     new_auth_key = f"{username}:{new_password}"
        #     chisel_users[new_auth_key] = old_ports.copy()
        #     print(colored(f"Added new credentials for user {username} in chisel users.json", "green"))

        #     # Keep the old entry to maintain existing connections
        #     print(colored(f"Keeping old credentials for user {username} to maintain existing connections", "yellow"))

        #     save_chisel_users(chisel_users)
        #     print(colored("Successfully updated chisel users.json", "green"))

        # # Restart Chisel server to apply changes
        # await restart_chisel_server()
        
        return {
            "message": "Password changed successfully",
            "warning": "IMPORTANT: Existing tunnel connections will continue to use the old password. New connections will require the new password. You may need to update your client configurations.",
            "details": {
                "existing_connections": "Will continue working with old password",
                "new_connections": "Will require new password",
                "action_needed": "Update client configurations for new connections"
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(colored(f"Error changing password: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail=str(e))

async def restart_chisel_server():
    """Restart the Chisel server to apply new configuration"""
    try:
        print(colored("Restarting Chisel server...", "yellow"))
        
        # Kill any existing chisel processes
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if 'chisel' in proc.info['name'].lower():
                    try:
                        psutil.Process(proc.info['pid']).kill()
                        print(colored(f"Killed existing Chisel process with PID {proc.info['pid']}", "yellow"))
                    except psutil.NoSuchProcess:
                        pass  # Process already terminated
            await asyncio.sleep(1)  # Wait for process to die
        except Exception as e:
            print(colored(f"Error killing existing Chisel process: {str(e)}", "yellow"))

        # Start new chisel process
        try:
            # Get absolute path to users.json
            current_dir = os.path.dirname(os.path.abspath(__file__))
            auth_file = os.path.join(current_dir, CHISEL_USERS_FILE)
            chisel_exe = os.path.join(current_dir, "chisel.exe" if os.name == "nt" else "chisel")
            
            cmd = [
                chisel_exe,
                "server",
                f"--authfile={auth_file}"
            ]
            
            is_windows = os.name == "nt"
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if is_windows else 0,
                cwd=current_dir
            )
            
            await asyncio.sleep(2)  # Wait for server to start
            
            if process.poll() is None:
                print(colored("Chisel server started successfully", "green"))
            else:
                stdout, stderr = process.communicate()
                error_msg = f"Chisel failed to start. stdout: {stdout.decode()}, stderr: {stderr.decode()}"
                print(colored(error_msg, "red"))
                return
                
        except Exception as e:
            print(colored(f"Error starting Chisel process: {str(e)}", "red"))
            return
            
    except Exception as e:
        print(colored(f"Error restarting Chisel server: {str(e)}", "red"))
        return

def get_used_ports() -> t.List[int]:
    try:
        connections = psutil.net_connections()
        return [conn.laddr.port for conn in connections if conn.status == 'LISTEN']
    except Exception as e:
        print(colored(f"Error getting used ports: {str(e)}", "red"))
        return []

def is_valid_port(port: int) -> bool:
    return isinstance(port, int) and 1 <= port <= 65535

def generate_chisel_client_command(username: str, password: str, remote_port: int, local_port: int) -> str:
    return f"chisel client --auth {username}:{password} http://{SERVER_CONFIG['server_url']}:{SERVER_CONFIG['chisel_port']} R:{remote_port}:localhost:{local_port}"

def get_user_password_from_chisel_users(username: str) -> str:
    """Get the user's password from chisel users file"""
    try:
        chisel_users = load_chisel_users()
        
        print(colored(f"Loaded chisel users: {chisel_users}", "cyan"))
        for auth_str, _ in chisel_users.items():
            user, password = auth_str.split(':')
            if user == username:
                return password
    except Exception as e:
        print(colored(f"Error getting user password: {str(e)}", "red"))
    return None

@app.get("/test")
async def test():
    return {"message": "API is working"}

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    try:
        print(colored("Attempting to render template", "yellow"))
        users = load_web_users()
        print(colored(f"Loaded users: {users}", "cyan"))
        response = templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "users": users
            }
        )
        print(colored("Template rendered successfully", "green"))
        return response
    except Exception as e:
        print(colored(f"Error rendering template: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail=str(e))
      


def get_all_local_port_data(chisel_users: dict) -> list:
    all_port_data = set()
    try:
        # chisel_users = load_chisel_users()
        for user, patterns in chisel_users.items():
            for pattern in patterns:
                if pattern.startswith('^0.0.0.0:'):
                    port_part = pattern.split(':')[-1].rstrip('$')
                    if port_part.isdigit():
                        all_port_data.add(int(port_part))
                    elif '[' in port_part and ']' in port_part:
                        range_match = re.match(r'\[(\d+)-(\d+)\]', port_part)
                        if range_match:
                            start, end = map(int, range_match.groups())
                            all_port_data.update(range(start, end + 1))
                    elif port_part == '[0-9]+':
                        all_port_data.update(range(1, 65536))  # All possible ports
    except Exception as e:
        print(colored(f"Error getting all local port data: {str(e)}", "red"))
    return list(all_port_data)



# TODO: change get_ports needs changing to use chisel_users to enumerate ports based on username if not admin for exposed_ports
@app.get("/api/ports")
async def get_ports(current_user: UserInDB = Depends(get_current_active_user)):
    try:
        used_ports = get_used_ports()
        web_users = load_web_users()
        chisel_users = load_chisel_users()
        all_local_ports = get_all_local_port_data(chisel_users)

        available_ports = [
            port for port in range(DEFAULT_PORT_RANGE[0], DEFAULT_PORT_RANGE[1])
            if port not in used_ports and port not in all_local_ports
        ]
        
        exposed_ports = {}
        
        # Helper function to get all chisel entries and passwords for a username
        def get_chisel_data_for_user(username: str) -> list:
            entries = []
            for chisel_key, patterns in chisel_users.items():
                chisel_username, chisel_password = chisel_key.split(':')
                if chisel_username == username:
                    for pattern in patterns:
                        if pattern:  # Skip empty patterns
                            entries.append((pattern, chisel_password))
            return entries

        # If admin, process all unique usernames from chisel_users
        # Otherwise, only process current user's entries
        if current_user.role == UserRole.ADMIN:
            unique_usernames = {key.split(':')[0] for key in chisel_users.keys()}
        else:
            unique_usernames = {current_user.username}
        
        for username in unique_usernames:
            port_patterns = get_chisel_data_for_user(username)
            
            for pattern, chisel_password in port_patterns:
                # Match both direct (0.0.0.0:port) and reverse (R:port) patterns
                port_match = re.search(r':(\d+)\$', pattern)
                if port_match:
                    remote_port = int(port_match.group(1))
                    local_port = remote_port  # Using same port for simplicity
                    port_key = f"{local_port}:{remote_port}"
                    
                    # Only process if:
                    # 1. User is admin (sees all tunnels) OR
                    # 2. Pattern is a reverse tunnel OR
                    # 3. Pattern belongs to current user
                    if (current_user.role == UserRole.ADMIN or 
                        pattern.startswith("^R:") or 
                        username == current_user.username):
                        
                        tunnel_type = "Reverse tunnel" if pattern.startswith("^R:") else "Direct tunnel"
                        
                        exposed_ports[port_key] = {
                            "username": username,
                            "description": f"{tunnel_type} for port {remote_port}",
                            "local_port": local_port,
                            "remote_port": remote_port,
                            "tunnel_type": "reverse" if pattern.startswith("^R:") else "direct",
                            "chisel_password": chisel_password,
                            "client_command": generate_chisel_client_command(
                                username,
                                chisel_password,
                                remote_port,
                                local_port
                            )
                        }

        print(colored(f"Retrieved port mappings for {'all users' if current_user.role == UserRole.ADMIN else 'current user'}", "green"))
        return {
            "used_ports": used_ports,
            "available_ports": available_ports,
            "exposed_ports": exposed_ports
        }
        
    except Exception as e:
        print(colored(f"Error getting ports: {str(e)}", "red"))
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to retrieve port information: {str(e)}"
        )
        
@app.get("/api/ports2")
async def get_ports2(current_user: UserInDB = Depends(get_current_active_user)):
    try:
        used_ports = get_used_ports()
        
        # Get all users' data
        web_users = load_web_users()
        chisel_users = load_chisel_users()
        all_local_ports = get_all_local_port_data(chisel_users)  # This now returns a list of integers

        available_ports = [
            port for port in range(DEFAULT_PORT_RANGE[0], DEFAULT_PORT_RANGE[1])
            if port not in used_ports and port not in all_local_ports
        ]
        
        
        # Build exposed ports from user permissions
        exposed_ports = {}
        
        # If admin, show all users' ports. If regular user, only show their own ports
        users_to_process = web_users if current_user.role == UserRole.ADMIN else {current_user.username: web_users[current_user.username]}
        
        for username, user_data in users_to_process.items():
            # Get user's password from chisel_users
            user_password = get_user_password_from_chisel_users(username)
            if not user_password:
                continue
            

            # Process each allowed port pattern
            for pattern in user_data.get("allowed_ports", []):
                # Extract port numbers from patterns
                port_match = re.search(r":(\d+)\$", pattern)
                if port_match:
                    remote_port = int(port_match.group(1))
                    local_port = remote_port  # Use same port for simplicity
                    port_key = f"{local_port}:{remote_port}"
                    # user_password = 
                    # For admin, show both regular and reverse tunnels
                    # For regular users, only show their own reverse tunnels
                    if current_user.role == UserRole.ADMIN or pattern.startswith("^R:"):
                        print(colored(f"Processing pattern: {pattern}", "cyan"))
                        tunnel_type = "Reverse tunnel" if pattern.startswith("^R:") else "Direct tunnel"
                        exposed_ports[port_key] = {
                            "username": username,
                            "description": f"{tunnel_type} for port {remote_port}",
                            "local_port": local_port,
                            "remote_port": remote_port,
                            "tunnel_type": "reverse" if pattern.startswith("^R:") else "direct",
                            "client_command": generate_chisel_client_command(
                                username,
                                user_password,
                                remote_port,
                                local_port
                            )
                        }
                        print(colored(f"Exposed ports: {exposed_ports}", "cyan"))
        
        print(colored(f"Retrieved port mappings for {'all users' if current_user.role == UserRole.ADMIN else 'current user'}", "green"))
        return {
            "used_ports": used_ports,
            "available_ports": available_ports,
            "exposed_ports": exposed_ports
        }
    except Exception as e:
        print(colored(f"Error getting ports: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ports/expose")
async def expose_port(port_data: PortExposure, current_user: UserInDB = Depends(get_current_active_user)):
    try:
        print(colored(f"Attempting to expose port with data: {port_data.dict()}", "cyan"))
        
        # Validate user permissions
        if current_user.role != UserRole.ADMIN and current_user.username != port_data.username:
            print(colored(f"User {current_user.username} is not authorized to expose ports for {port_data.username}", "red"))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only expose ports for your own user unless you're an admin"
            )
        
        if not is_valid_port(port_data.local_port) or not is_valid_port(port_data.remote_port):
            print(colored(f"Invalid port number: local_port={port_data.local_port}, remote_port={port_data.remote_port}", "red"))
            raise HTTPException(status_code=400, detail="Invalid port number")

        # Check if ports are in the allowed range
        if not (DEFAULT_PORT_RANGE[0] <= port_data.local_port <= DEFAULT_PORT_RANGE[1] and 
                DEFAULT_PORT_RANGE[0] <= port_data.remote_port <= DEFAULT_PORT_RANGE[1]):
            raise HTTPException(
                status_code=400, 
                detail=f"Ports must be between {DEFAULT_PORT_RANGE[0]} and {DEFAULT_PORT_RANGE[1]}"
            )

        # Check if local port is already in use by the system
        used_ports = get_used_ports()
        if port_data.local_port in used_ports:
            print(colored(f"Local port {port_data.local_port} is already in use by the system", "red"))
            raise HTTPException(
                status_code=400, 
                detail=f"Local port {port_data.local_port} is already in use by the system"
            )

        # Load users data
        web_users = load_web_users()
        if port_data.username not in web_users:
            raise HTTPException(status_code=404, detail="User not found")
            
        user = web_users[port_data.username]
        
        # Check if port is already allowed for this user
        port_patterns = [
            f"^R:0.0.0.0:{port_data.remote_port}$",
            f"^0.0.0.0:{port_data.remote_port}$"
        ]
        
        if "allowed_ports" not in user:
            user["allowed_ports"] = []

        # Check if any other user already has this port
        for other_username, other_user in web_users.items():
            if other_username != port_data.username:
                for pattern in other_user.get("allowed_ports", []):
                    if any(p in pattern for p in port_patterns):
                        raise HTTPException(
                            status_code=400, 
                            detail=f"Port {port_data.remote_port} is already assigned to user {other_username}"
                        )

        # Check if the port is already in use by Chisel
        try:
            chisel_response = requests.get(f"http://localhost:{port_data.remote_port}", timeout=1)
            if chisel_response.status_code != 502:  # Chisel returns 502 for unused ports
                raise HTTPException(
                    status_code=400,
                    detail=f"Port {port_data.remote_port} appears to be already in use by a Chisel tunnel"
                )
        except requests.exceptions.RequestException:
            # If connection fails, port is likely free
            pass

        # Add port patterns to user's allowed ports
        for pattern in port_patterns:
            if pattern not in user["allowed_ports"]:
                user["allowed_ports"].append(pattern)
        
        # Save updated user data
        save_web_users(web_users)
        print(colored(f"Updated web user {port_data.username} with new port patterns", "green"))
        
        # Update chisel users
        chisel_users = load_chisel_users()
        user_password = get_user_password_from_chisel_users(port_data.username)
        if not user_password:
            raise HTTPException(status_code=500, detail="Could not find user's chisel credentials")
            
        chisel_key = f"{port_data.username}:{user_password}"
        if chisel_key not in chisel_users:
            chisel_users[chisel_key] = []
            
        for pattern in port_patterns:
            if pattern not in chisel_users[chisel_key]:
                chisel_users[chisel_key].append(pattern)
                
        save_chisel_users(chisel_users)
        print(colored(f"Updated chisel user {port_data.username} with new port patterns", "green"))
        
        # Generate client command
        client_command = generate_chisel_client_command(
            port_data.username,
            user_password,
            port_data.remote_port,
            port_data.local_port
        )
        
        await restart_chisel_server()
        print(colored("Chisel server restarted successfully", "green"))
        
        return {
            "message": "Port exposed successfully",
            "client_command": client_command
        }
    except HTTPException:
        raise
    except Exception as e:
        print(colored(f"Unexpected error exposing port: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.delete("/api/ports/expose/{local_port}/{remote_port}")
async def unexpose_port(local_port: int, remote_port: int, current_user: UserInDB = Depends(get_current_active_user)):
    try:
        if not is_valid_port(local_port) or not is_valid_port(remote_port):
            raise HTTPException(status_code=400, detail="Invalid port number")

        # Load users data
        web_users = load_web_users()
        
        # Find the user who owns this port
        port_owner = None
        port_patterns = [
            f"^R:0.0.0.0:{remote_port}$",
            f"^0.0.0.0:{remote_port}$"
        ]
        
        for username, user in web_users.items():
            for pattern in user.get("allowed_ports", []):
                if any(p in pattern for p in port_patterns):
                    port_owner = username
                    break
            if port_owner:
                break
                
        if not port_owner:
            raise HTTPException(status_code=404, detail="Port mapping not found")
        
        # Check user permissions
        if current_user.role != UserRole.ADMIN and current_user.username != port_owner:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only remove your own port mappings unless you're an admin"
            )
        
        # Remove port patterns from user's allowed ports
        user = web_users[port_owner]
        for pattern in port_patterns:
            if pattern in user["allowed_ports"]:
                user["allowed_ports"].remove(pattern)
        
        save_web_users(web_users)
        print(colored(f"Removed port patterns for user {port_owner}", "green"))
        
        # Update chisel users
        chisel_users = load_chisel_users()
        user_password = get_user_password_from_chisel_users(port_owner)
        if user_password:
            chisel_key = f"{port_owner}:{user_password}"
            if chisel_key in chisel_users:
                for pattern in port_patterns:
                    if pattern in chisel_users[chisel_key]:
                        chisel_users[chisel_key].remove(pattern)
                save_chisel_users(chisel_users)
                print(colored(f"Updated chisel user {port_owner}", "green"))
        
        await restart_chisel_server()
        print(colored("Chisel server restarted successfully", "green"))
        
        return {"message": "Port unexposed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(colored(f"Error unexposing port: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/install-client/{config}")
async def get_install_client(config: str, token: str = None):
    try:
        # Verify token
        if not token:
            raise HTTPException(status_code=401, detail="Not authenticated")
            
        try:
            # Decode and verify the token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username:
                raise HTTPException(status_code=401, detail="Invalid token")
                
            # Load user data
            web_users = load_web_users()
            if username not in web_users:
                raise HTTPException(status_code=404, detail="User not found")
                
            current_user = UserInDB(**web_users[username])
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Parse config string (username:password:localport:remoteport)
        try:
            config_username, password, local_port, remote_port = config.split(":")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid configuration format")
            
        # Validate ports
        try:
            local_port = int(local_port)
            remote_port = int(remote_port)
            if not (1 <= local_port <= 65535 and 1 <= remote_port <= 65535):
                raise ValueError("Invalid port numbers")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid port numbers")

        # Check permissions
        if current_user.role != UserRole.ADMIN and current_user.username != config_username:
            raise HTTPException(
                status_code=403,
                detail="You can only generate installation scripts for your own ports unless you're an admin"
            )

        # Verify the password matches
        chisel_users = load_chisel_users()
        auth_key = f"{config_username}:{password}"
        if auth_key not in chisel_users:
            raise HTTPException(status_code=403, detail="Invalid credentials")

        # Read template files
        try:
            with open("install_client.sh", "r", encoding="utf-8") as f:
                install_script = f.read()
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="Installation template not found")

        # Create combined installation script with environment variables
        combined_script = f"""#!/bin/bash

# Set configuration variables
export SERVER_URL="{SERVER_CONFIG['server_url']}:{SERVER_CONFIG['chisel_port']}"
export USERNAME="{config_username}"
export PASSWORD="{password}"
export LOCAL_PORT="{local_port}"
export REMOTE_PORT="{remote_port}"

# Create temporary config file
cat > chisel-client.template.conf << 'EOL'
# Chisel Client Configuration Template

# Server Configuration
SERVER_URL="${{SERVER_URL}}"
USERNAME="${{USERNAME}}"
PASSWORD="${{PASSWORD}}"

# Port Configuration
LOCAL_PORT="${{LOCAL_PORT}}"
REMOTE_PORT="${{REMOTE_PORT}}"

# Service Configuration
SERVICE_NAME="chisel-client"
SERVICE_DESCRIPTION="Chisel Client Tunnel Service"

# Installation Options
INSTALL_DIR="/usr/local/bin"  # Linux/macOS default
WINDOWS_INSTALL_DIR="C:\\\\Program Files\\\\Chisel"  # Windows default

# Auto-start Options
AUTO_START="yes"
RESTART_ON_FAILURE="yes"
RESTART_DELAY="10"

# Logging Options
ENABLE_LOGGING="yes"
LOG_LEVEL="info"

# Security Options
TLS_SKIP_VERIFY="no"

# Advanced Options
KEEPALIVE="25s"
MAX_RETRY_COUNT="0"
MAX_RETRY_INTERVAL="5m"
EOL

# Replace placeholders in configuration file
sed -i "s|\\${{SERVER_URL}}|$SERVER_URL|g" chisel-client.template.conf
sed -i "s|\\${{USERNAME}}|$USERNAME|g" chisel-client.template.conf
sed -i "s|\\${{PASSWORD}}|$PASSWORD|g" chisel-client.template.conf
sed -i "s|\\${{LOCAL_PORT}}|$LOCAL_PORT|g" chisel-client.template.conf
sed -i "s|\\${{REMOTE_PORT}}|$REMOTE_PORT|g" chisel-client.template.conf

# Create installation script
cat > install_client.sh << 'EOL'
{install_script}
EOL

# Make script executable
chmod +x install_client.sh

# Run installation
./install_client.sh

# Cleanup
rm install_client.sh chisel-client.template.conf
"""
        
        return Response(
            content=combined_script,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=install-chisel.sh"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        print(colored(f"Error generating installation script: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/server-config")
async def get_server_config(current_user: UserInDB = Depends(get_current_active_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can view server configuration"
        )
    return SERVER_CONFIG

@app.put("/api/server-config")
async def update_server_config(
    config: ServerConfig,
    current_user: UserInDB = Depends(get_current_active_user)
):
    try:
        if current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can update server configuration"
            )

        # Validate server URL format
        if not re.match(r'^[a-zA-Z0-9.-]+$', config.server_url):
            raise HTTPException(
                status_code=400,
                detail="Invalid server URL format"
            )

        # Validate port number
        if not (1 <= config.chisel_port <= 65535):
            raise HTTPException(
                status_code=400,
                detail="Invalid port number"
            )

        # Update configuration
        global SERVER_CONFIG, SERVER_IP
        SERVER_CONFIG = {
            "server_url": config.server_url,
            "web_port": config.web_port,
            "chisel_port": config.chisel_port
        }
        SERVER_IP = config.server_url
        
        # Save configuration
        save_server_config(SERVER_CONFIG)
        
        # Restart Chisel server to apply changes
        await restart_chisel_server()
        
        return {
            "message": "Server configuration updated successfully",
            "config": SERVER_CONFIG
        }
    except HTTPException:
        raise
    except Exception as e:
        print(colored(f"Error updating server configuration: {str(e)}", "red"))
        raise HTTPException(status_code=500, detail=str(e))

# Define run_app at module level for Windows multiprocessing
def run_app():
    import uvicorn
    import psutil
    import os
    
    # Check if another instance is already running on port 8000
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == 8000 and conn.status == 'LISTEN':
                print(colored(f"Another instance is already running on port 8000 (PID: {conn.pid})", "yellow"))
                return
    except Exception as e:
        print(colored(f"Error checking for existing instances: {str(e)}", "red"))

    # Create a marker file to indicate this instance is running
    marker_file = os.path.join(os.path.dirname(__file__), ".instance_running")
    
    # Check if marker file exists and validate the PID
    if os.path.exists(marker_file):
        try:
            with open(marker_file, "r", encoding="utf-8") as f:
                old_pid = int(f.read().strip())
            
            # Check if the process with this PID is still running
            try:
                process = psutil.Process(old_pid)
                if process.is_running() and "python" in process.name().lower():
                    print(colored(f"Another instance is already running with PID: {old_pid}", "yellow"))
                    return
                else:
                    print(colored("Found stale marker file, removing it...", "yellow"))
                    os.remove(marker_file)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                print(colored("Found stale marker file, removing it...", "yellow"))
                os.remove(marker_file)
        except Exception as e:
            print(colored(f"Error reading marker file: {str(e)}", "red"))
            # Remove invalid marker file
            try:
                os.remove(marker_file)
            except:
                pass

    try:
        # Create new marker file
        with open(marker_file, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        
        print(colored(f"Starting new instance (PID: {os.getpid()})", "green"))
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=False,  # Disable uvicorn's reloader
            log_level="info"
        )
    finally:
        # Clean up marker file when the process exits
        try:
            if os.path.exists(marker_file):
                os.remove(marker_file)
        except Exception as e:
            print(colored(f"Error removing marker file: {str(e)}", "red"))

if __name__ == "__main__":
    import uvicorn
    import sys
    
    print(colored("Starting Chisel Control Panel...", "cyan"))
    
    try:
        # Run without file watching in production mode
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=False,  # Disable reload to prevent loops
            log_level="info"
        )
    except Exception as e:
        print(colored(f"Error starting server: {str(e)}", "red"))
        sys.exit(1) 