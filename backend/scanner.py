import psutil #running processes
from collections import Counter #counting occurrences

processes = []


for p in psutil.process_iter([
    "pid",
    "name",
    "exe",
    "cpu_percent",
    "memory_info"
]):
    try:
        processes.append(p.info) #add process info to list
    except psutil.Error:
        continue


dirs = []
for p in processes:
    d = get_dir(p["exe"])
    if d:
        dirs.append(d)
dir_frequency = Counter(dirs)

TOTAL = len(processes)

def get_dir(path): #get the dir without the filename
    if not path:
        return None
    parts = path.replace("\\", "/").split("/") #Windows paths use backslashes \ but splitting on \ is annoying in python. now we're getting every folder in the path seperated
    if len(parts) <= 1:
        return None
    return "/".join(parts[:-1]) #return everything but the last part (the filename) 
#join() takes a list of strings and glues them together using the string before .join()


def is_rare_path(path):
    d = get_dir(path)
    if not d:
        return True
    return dir_frequency[d] / TOTAL < 0.02  # less than 2%




