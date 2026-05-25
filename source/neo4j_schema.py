from neo4j import GraphDatabase
from config import settings

EMBEDDING_DIM = 768  # change if needed

SCHEMA_QUERIES = [
    # -------------------------
    # Core uniqueness constraints
    # -------------------------
    """
    CREATE CONSTRAINT vulnerability_cve_id IF NOT EXISTS
    FOR (n:Vulnerability)
    REQUIRE n.cve_id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT vendor_key IF NOT EXISTS
    FOR (n:Vendor)
    REQUIRE n.key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT software_key IF NOT EXISTS
    FOR (n:Software)
    REQUIRE n.key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT software_version_key IF NOT EXISTS
    FOR (n:SoftwareVersion)
    REQUIRE n.key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT operating_system_value IF NOT EXISTS
    FOR (n:OperatingSystem)
    REQUIRE n.value IS UNIQUE
    """,
    """
    CREATE CONSTRAINT user_interaction_value IF NOT EXISTS
    FOR (n:UserInteraction)
    REQUIRE n.value IS UNIQUE
    """,
    """
    CREATE CONSTRAINT network_access_value IF NOT EXISTS
    FOR (n:NetworkAccess)
    REQUIRE n.value IS UNIQUE
    """,
    """
    CREATE CONSTRAINT privilege_value IF NOT EXISTS
    FOR (n:Privilege)
    REQUIRE n.value IS UNIQUE
    """,

    # -------------------------
    # Semantic exact-text merged nodes
    # source and system_state are now semantic fields.
    # -------------------------
    """
    CREATE CONSTRAINT source_value_key IF NOT EXISTS
    FOR (n:Source)
    REQUIRE n.value_key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT system_state_value_key IF NOT EXISTS
    FOR (n:SystemState)
    REQUIRE n.value_key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT reason_value_key IF NOT EXISTS
    FOR (n:Reason)
    REQUIRE n.value_key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT attacker_action_value_key IF NOT EXISTS
    FOR (n:AttackerAction)
    REQUIRE n.value_key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT consequence_value_key IF NOT EXISTS
    FOR (n:Consequence)
    REQUIRE n.value_key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT trigger_value_key IF NOT EXISTS
    FOR (n:Trigger)
    REQUIRE n.value_key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT vulnerability_type_value_key IF NOT EXISTS
    FOR (n:VulnerabilityType)
    REQUIRE n.value_key IS UNIQUE
    """,

    # -------------------------
    # Full-text indexes
    # -------------------------
    """
    CREATE FULLTEXT INDEX vulnerability_description_ft IF NOT EXISTS
    FOR (n:Vulnerability)
    ON EACH [n.description]
    """,
    """
    CREATE FULLTEXT INDEX semantic_source_ft IF NOT EXISTS
    FOR (n:Source)
    ON EACH [n.value]
    """,
    """
    CREATE FULLTEXT INDEX semantic_system_state_ft IF NOT EXISTS
    FOR (n:SystemState)
    ON EACH [n.value]
    """,
    """
    CREATE FULLTEXT INDEX semantic_reason_ft IF NOT EXISTS
    FOR (n:Reason)
    ON EACH [n.value]
    """,
    """
    CREATE FULLTEXT INDEX semantic_attacker_action_ft IF NOT EXISTS
    FOR (n:AttackerAction)
    ON EACH [n.value]
    """,
    """
    CREATE FULLTEXT INDEX semantic_consequence_ft IF NOT EXISTS
    FOR (n:Consequence)
    ON EACH [n.value]
    """,
    """
    CREATE FULLTEXT INDEX semantic_trigger_ft IF NOT EXISTS
    FOR (n:Trigger)
    ON EACH [n.value]
    """,
    """
    CREATE FULLTEXT INDEX semantic_vulnerability_type_ft IF NOT EXISTS
    FOR (n:VulnerabilityType)
    ON EACH [n.value]
    """,

    # -------------------------
    # Vector indexes
    # -------------------------
    f"""
    CREATE VECTOR INDEX source_embedding_idx IF NOT EXISTS
    FOR (n:Source)
    ON (n.embedding)
    OPTIONS {{indexConfig: {{
      `vector.dimensions`: {EMBEDDING_DIM},
      `vector.similarity_function`: 'cosine'
    }}}}
    """,
    f"""
    CREATE VECTOR INDEX system_state_embedding_idx IF NOT EXISTS
    FOR (n:SystemState)
    ON (n.embedding)
    OPTIONS {{indexConfig: {{
      `vector.dimensions`: {EMBEDDING_DIM},
      `vector.similarity_function`: 'cosine'
    }}}}
    """,
    f"""
    CREATE VECTOR INDEX reason_embedding_idx IF NOT EXISTS
    FOR (n:Reason)
    ON (n.embedding)
    OPTIONS {{indexConfig: {{
      `vector.dimensions`: {EMBEDDING_DIM},
      `vector.similarity_function`: 'cosine'
    }}}}
    """,
    f"""
    CREATE VECTOR INDEX attacker_action_embedding_idx IF NOT EXISTS
    FOR (n:AttackerAction)
    ON (n.embedding)
    OPTIONS {{indexConfig: {{
      `vector.dimensions`: {EMBEDDING_DIM},
      `vector.similarity_function`: 'cosine'
    }}}}
    """,
    f"""
    CREATE VECTOR INDEX consequence_embedding_idx IF NOT EXISTS
    FOR (n:Consequence)
    ON (n.embedding)
    OPTIONS {{indexConfig: {{
      `vector.dimensions`: {EMBEDDING_DIM},
      `vector.similarity_function`: 'cosine'
    }}}}
    """,
    f"""
    CREATE VECTOR INDEX trigger_embedding_idx IF NOT EXISTS
    FOR (n:Trigger)
    ON (n.embedding)
    OPTIONS {{indexConfig: {{
      `vector.dimensions`: {EMBEDDING_DIM},
      `vector.similarity_function`: 'cosine'
    }}}}
    """,
    f"""
    CREATE VECTOR INDEX vulnerability_type_embedding_idx IF NOT EXISTS
    FOR (n:VulnerabilityType)
    ON (n.embedding)
    OPTIONS {{indexConfig: {{
      `vector.dimensions`: {EMBEDDING_DIM},
      `vector.similarity_function`: 'cosine'
    }}}}
    """
]


def main() -> None:
    driver = GraphDatabase.driver(
        settings.uri,
        auth=(settings.user, settings.password)
    )
    try:
        with driver.session(database=settings.database) as session:
            for query in SCHEMA_QUERIES:
                session.run(query)
        print("Schema created successfully.")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
