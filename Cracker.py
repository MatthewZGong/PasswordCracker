import sys
import hashlib
#stop at BU
LETTERS = "a b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 0"
#1gumbo
PASSWORD_LIST = "rockyou.txt"

def generate_salt_length_2():
    letters = LETTERS.split()
    for i in letters: 
        for j in letters: 
             salt = i+j
             yield salt

def compute_sha256_salt_append(word, salt):
    hash = hashlib.sha256()
    ws = word + salt
    hash.update(ws.encode('utf-8'))
    return hash.hexdigest()

def load_password_list(): 
    password_list = []
    with open(PASSWORD_LIST, "r") as file: 
            for line in file: 
                password_list.append(line.strip())
    return password_list

def load_formspring_hashes(file_name): 
    hashed_passwords = set()
    with open(file_name, "r") as file: 
            for line in file: 
                hashed_passwords.add(line.strip())
    return hashed_passwords 

def break_formsrping_hashes(file_name): 
    hashed_passwords = load_formspring_hashes(file_name)
    password_list = load_password_list()
    with open('formpsring_cracked.txt', 'w', encoding="utf8") as out_file:
        for salt in generate_salt_length_2(): 
            print(salt)
            for password in password_list: 
                hash = compute_sha256_salt_append(password, salt)
                if hash in hashed_passwords: 
                    print(f"Match found: '{password}' | Hash: {hash} | Salt: {salt}")
                    out_file.write(f"Match found: '{password}' | Hash: {hash} | Salt: {salt}\n")

#For solving linkedin
def compute_sha1_hash_no_salt(word):
    return hashlib.sha1(word.encode()).hexdigest()
def load_password_dict_hashed(): 
    word_dict = {}
    with open(PASSWORD_LIST, "r") as file: 
            for line in file: 
                word_dict[compute_sha1_hash_no_salt(line.strip())] = line.strip()
    return word_dict

def break_file_linkedin(filename, n = None): 
    hashed_pass_dict = load_password_dict_hashed() 
    if(filename == None or filename == ""):
        return
     
    with open(filename, "r") as file, open('output.txt', 'w', encoding="utf8") as out_file: 
        i = 0
        counter = 0
        for line in file: 
            i += 1   
            hash = line.strip()       
            if(counter < 100 and hash in hashed_pass_dict):
                out_file.write(f"{hash} {hashed_pass_dict[hash]}\n")
                counter += 1
def yahoo_solve():
    with open("./LeakedPasswordLists/yahoo/password.file", "r", errors="ignore") as file, open('output.txt', 'w', encoding="utf8") as out_file: 
        counter = 0
        for line in file:
            l = line.strip()
            l = l.split(":")
            if(len(l) >= 3): 
                if counter < 100 and l[0].isdigit(): 
                    counter += 1
                    out_file.write(f"{l[2]} {l[2]}\n")

if __name__ == '__main__': 
    # filename = sys.argv[1]
    # s = compute_sha1_hash_no_salt("ciencias".strip())
    yahoo_solve()
    # print(s)
    # break_formsrping_hashes(filename)
    # break_file_linkedin(filename)
    