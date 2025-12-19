import pandas as pd
from faker import Faker
import random

fake = Faker()

def generate_shadow_db():
    print("Generating Enterprise Shadow Database...")
    data = []
    departments = ['hr', 'it.sec', 'finance', 'legal', 'eng', 'sales', 'c-suite', 'devops']
    domains = ['@apex-corp.internal', '@apex-partners.net', '@zurich-secure.io']
    statuses = ['Unread', 'Read', 'Replied', 'High Priority', 'Flagged', 'Archived']
    subjects = ["Q3 Financial Report", "Security Patch Required", "Employee Handbook", "Invoice Payment", "Server Downtime", "Password Expiration", "Client Onboarding", "Budget Approval", "Project Titan"]

    for i in range(1000, 6000):
        dept = random.choice(departments)
        sender = f"{dept}.{fake.last_name().lower()}{random.choice(domains)}"
        row = {
            "id": i,
            "sender": sender,
            "subject": f"{random.choice(subjects)} - {fake.bothify(text='Ref:??-####')}",
            "date": fake.date_between(start_date='-1y', end_date='today'),
            "status": random.choice(statuses)
        }
        data.append(row)

    df = pd.DataFrame(data)
    df.to_csv("fake_emails.csv", index=False)
    print("Shadow Database 'fake_emails.csv' Created.")

if __name__ == "__main__":
    generate_shadow_db()