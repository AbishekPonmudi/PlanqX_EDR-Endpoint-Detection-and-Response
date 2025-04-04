import psutil
import time

while True:
    cpu_usage = psutil.cpu_percent(interval=1)
    mem_info = psutil.virtual_memory()
    print(f"CPU Usage: {cpu_usage}%")
    print(f"Memory Usage: {mem_info.percent}%")
    time.sleep(1)
