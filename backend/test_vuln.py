import asyncio
from app.models.database import engine
from app.api.routes import list_vulnerabilities
from sqlalchemy.ext.asyncio import async_sessionmaker

async def test():
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as db:
        try:
            res = await list_vulnerabilities(db)
            print("SUCCESS:", res)
        except Exception as e:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
