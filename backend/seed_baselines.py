import asyncio
from app.models.database import engine
from app.models.schemas import GoldenBaseline
from sqlalchemy.ext.asyncio import async_sessionmaker

async def seed():
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as db:
        b1 = GoldenBaseline(
            name='Web Server Lockdown',
            description='Strict rules for public-facing web servers.',
            framework='NIST SP 800-53',
            rules=[
                {'port': 22, 'state': 'closed', 'description': 'SSH must not be exposed'},
                {'port': 80, 'state': 'open', 'description': 'HTTP allowed'},
                {'port': 443, 'state': 'open', 'description': 'HTTPS allowed'}
            ]
        )
        b2 = GoldenBaseline(
            name='Database Server Baseline',
            description='Internal DB servers should have no public ports open except SQL.',
            framework='CIS Benchmarks',
            rules=[
                {'port': 3306, 'state': 'open', 'description': 'MySQL port'},
                {'port': 80, 'state': 'closed', 'description': 'No web server on DB node'}
            ]
        )
        db.add_all([b1, b2])
        await db.commit()
        print('Seeded baselines!')

if __name__ == "__main__":
    asyncio.run(seed())
