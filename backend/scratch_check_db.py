import asyncio
from sqlalchemy import select
from app.models.database import async_session
from app.models.schemas import Scan

async def check():
    async with async_session() as db:
        res = await db.execute(select(Scan))
        scans = res.scalars().all()
        print('Scans in DB:')
        for s in scans:
            print(f"ID: {s.id}, Target: {s.target}")

if __name__ == "__main__":
    asyncio.run(check())
