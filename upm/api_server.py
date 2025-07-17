# upm/api_server.py

import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional, Dict, Any, Union # Keep standard typing imports

# Removed TypedDict related aliases from api_server.py, as core.py now uses BaseModel
# from upm.core import OperationResult as CoreOperationResult
# from upm.core import ListOperationResult as CoreListOperationResult
# from upm.core import SearchOperationResult as CoreSearchOperationResult
# from upm.core import SearchResult as CoreSearchResult # For SearchOperationResult's internal type

# IMPORT THE ACTUAL PYDANTIC BASEMODEL CLASSES FROM upm.core
from upm.core import UniversalPackageManager, OperationResult, ListOperationResult, SearchOperationResult, SearchResultResponse # SearchResultResponse is the BaseModel for individual search results


# --- FastAPI App and UPM Core Initialization ---
app = FastAPI(
    title="Universal Package Manager API",
    description="Programmatic control over UPM for CI/CD and automation.",
    version="1.0.0"
)

# The API server creates a single, shared instance of the UPM core engine.
upm = UniversalPackageManager(project_root=os.getcwd())

# --- Authentication Implementation ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def validate_token(token: str = Depends(oauth2_scheme)):
    """A placeholder for a real token validation function."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 password flow to obtain an access token.
    --- THIS IS A DUMMY IMPLEMENTATION FOR DEMONSTRATION ---
    """
    if form_data.username == "user" and form_data.password == "pass":
        access_token = "dummy_access_token_for_" + form_data.username
        return {"access_token": access_token, "token_type": "bearer"}
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

# --- Protected API Endpoints ---

@app.post("/install", response_model=OperationResult, tags=["Package Management"])
async def install_package(install_request: dict, token: str = Depends(validate_token)):
    """
    Installs a package in a given ecosystem. Requires authentication.
    """
    result = await upm.install(
        ecosystem=install_request.get("eco"),
        package=install_request.get("name"),
        version=install_request.get("version")
    )
    if not result.success: # Access BaseModel attribute directly
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result.model_dump()) # Use .model_dump() for details
    return result

@app.get("/list", response_model=ListOperationResult, tags=["Package Management"])
async def list_packages(ecosystem: Optional[str] = None, token: str = Depends(validate_token)):
    """
    Lists all installed packages, optionally filtered by ecosystem. Requires authentication.
    """
    result = await upm.list_packages(ecosystem=ecosystem)
    if not result.success: # Access BaseModel attribute directly
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.model_dump()) # Use .model_dump() for details
    return result

@app.get("/search", response_model=SearchOperationResult, tags=["Package Management"])
async def search_packages(ecosystem: str, query: str, token: str = Depends(validate_token)):
    """
    Searches for a package in a specific ecosystem. Requires authentication.
    """
    result = await upm.search(ecosystem, query)
    if not result.success: # Access BaseModel attribute directly
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.model_dump()) # Use .model_dump() for details
    return result

@app.get("/doctor", response_model=OperationResult, tags=["Project Health"])
async def run_doctor_check(ecosystem: Optional[str] = None, token: str = Depends(validate_token)):
    """
    Runs a full health check on the project. Requires authentication.
    """
    result = await upm.doctor()
    if not result.success: # Access BaseModel attribute directly
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.model_dump()) # Use .model_dump() for details
    return result

# --- Health Check Endpoint (Public) ---
@app.get("/", tags=["General"])
def read_root():
    """Health check endpoint to confirm the API is running."""
    return {"message": "Welcome to the Universal Package Manager API!", "version": "1.0.0"}