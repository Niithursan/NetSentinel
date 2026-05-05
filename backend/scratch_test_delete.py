import asyncio
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.models.database import async_session
from app.models.schemas import Scan, Host

async def test_delete():
    async with async_session() as db:
        print("Fetching scan 1...")
        stmt = (
            select(Scan)
            .options(
                selectinload(Scan.hosts).selectinload(Host.ports),
                selectinload(Scan.hosts).selectinload(Host.vulnerabilities),
            )
            .where(Scan.id == 1)
        )
        result = await db.execute(stmt)
        scan = result.scalar_one_or_none()
        
        if not scan:
            print("Scan 1 not found.")
            return
            
        print(f"Found scan 1. Hosts: {len(scan.hosts)}")
        print("Attempting to delete...")
        
        try:
            await db.delete(scan)
            await db.commit()
            print("Deletion successful!")
        except Exception as e:
            print(f"Deletion failed with error: {type(e).__name__} - {e}")
            await db.rollback()

if __name__ == "__main__":
    asyncio.run(test_delete())
