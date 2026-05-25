from dataclasses import dataclass
import os
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Settings:
    uri: str = os.getenv("NEO4J_URI", "neo4j://127.0.0.1:7687")
    user: str = os.getenv("NEO4J_USER", "neo4j")
    password: str = os.getenv("NEO4J_PASSWORD", "neo4j1234")
    database: str = os.getenv("NEO4J_DATABASE", "neo4j")

settings = Settings()