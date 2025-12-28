import pefile
import lief
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re

def analyze_pe(file_path):
    result = []

    try:
        pe = pefile.PE(file_path) # PE = 파일(exe) 전체 설계도 
        binary = lief.parse(file_path)

        result.append("[+] 기본 정보")
        result.append(f"시작 CPU 주소: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
        result.append(f"메모리 주소: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
        result.append(f"실행 환경: {pe.OPTIONAL_HEADER.Subsystem}")
        result.append("")

        result.append("[+] 섹션 정보") # 섹션 = 역할별 공간
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00")
            result.append(f"{name} | Size: {section.Misc_VirtualSize}")
        result.append("")

        result.append("[+] Import DLL 목록") # DLL = 외부 기능
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                result.append(entry.dll.decode())
        else:
            result.append("Import 없음")
        result.append("")

        result.append("[+] 문자열 분석")
        with open(file_path, "rb") as f:
            data = f.read()
            strings = re.findall(rb"[ -~]{5,}", data)
            for s in strings[:100]:
                result.append(s.decode(errors="ignore"))

    except Exception as e:
        messagebox.showerror("오류", str(e))

    return "\n".join(result)

def open_file():
    file_path = filedialog.askopenfilename(
        title="PE 파일 선택",
        filetypes=[("Executable Files", "*.exe")]
    )

    if not file_path:
        return

    output.delete(1.0, tk.END)
    output.insert(tk.END, analyze_pe(file_path))

root = tk.Tk()
root.title("AutoRE")
root.geometry("800x600")

btn = tk.Button(root, text="파일 분석", command=open_file)
btn.pack(pady=10)

output = scrolledtext.ScrolledText(root, wrap=tk.WORD)
output.pack(expand=True, fill=tk.BOTH)

root.mainloop()
