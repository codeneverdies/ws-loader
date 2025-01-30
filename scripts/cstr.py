import sys

def main():

    done = ""
    func_name = sys.argv[1]
    sz = len(func_name)

    for i in func_name:
        done += f"'{i}', "
    print(f"CHAR str_{func_name}[] = {{", done + "0 };")
    print(f"{{", done + "0x0 };")

main()
