import pandas as pd
import os
from datetime import datetime

def log_to_excel(username, attack_type, ip_address, city="Unknown", country="Unknown", isp="Unknown", conn_type="Unknown"):
    today_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"Attack_Logs_{today_str}.xlsx"
    
    new_data = {
        "Timestamp": [datetime.now().strftime("%H:%M:%S")],
        "Attack Type": [attack_type],
        "IP Address": [ip_address],
        "City": [city],
        "Country": [country],
        "ISP": [isp],
        "Connection": [conn_type],
        "Payload": [username],
        "Status": ["DECEIVED"]
    }
    new_df = pd.DataFrame(new_data)

    try:
        if os.path.exists(filename):
            existing_df = pd.read_excel(filename)
            updated_df = pd.concat([existing_df, new_df], ignore_index=True)
            updated_df.to_excel(filename, index=False)
        else:
            new_df.to_excel(filename, index=False)
    except:
        pass