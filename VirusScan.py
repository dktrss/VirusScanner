import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
import threading
import requests
import os
import hashlib

API_KEY = "____insert api____"
VT_LARGE_UPLOAD_URL = "https://www.virustotal.com/api/v3/files/upload_url"
VT_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/{}"
VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/{}"
MAX_FILE_SIZE = 1000 * 1024 * 1024

class VirusScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Virus Scanner")
        self.root.geometry("500x300")
        self.root.configure(bg="#0d1014")

        self.label = tk.Label(
            root,
            text="Drop a file here",
            bg="#0d1014",
            fg="white",
            font=("Lucida Console", 16)
        )
        self.label.pack(expand=True, fill="both")
        self.label.bind("<Button-1>", self.select_file)

        self.label.drop_target_register(DND_FILES)
        self.label.dnd_bind("<<Drop>>", self.on_drop)

    def select_file(self, event=None):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.start_scan(file_path)

    def on_drop(self, event):
        file_path = event.data.strip("{}")
        if os.path.isfile(file_path):
            self.start_scan(file_path)
        else:
            messagebox.showerror("Error", "Invalid file dropped.")

    def start_scan(self, file_path):
        self.label.config(text="Scanning...")
        self.root.update()
        threading.Thread(target=self.scan_and_display, args=(file_path,), daemon=True).start()

    def scan_and_display(self, file_path):
        result = self.scan_file(file_path)
        self.root.after(0, lambda: self.display_result(result))

    def compute_sha256(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get_existing_report(self, file_hash, headers):
        response = requests.get(VT_FILE_REPORT_URL.format(file_hash), headers=headers)
        if response.status_code == 200:
            return response.json()["data"]["attributes"].get("last_analysis_results", {})
        return None

    def scan_file(self, file_path):
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                return f"Error: File exceeds 1000MB limit.\nSize: {file_size / (1024*1024):.2f} MB"

            headers = {"x-apikey": API_KEY}
            file_hash = self.compute_sha256(file_path)
            results = self.get_existing_report(file_hash, headers)

            if not results:
                upload_url_response = requests.get(VT_LARGE_UPLOAD_URL, headers=headers)
                upload_url_response.raise_for_status()
                upload_url = upload_url_response.json()["data"]

                with open(file_path, "rb") as f:
                    files = {"file": (os.path.basename(file_path), f)}
                    upload_response = requests.post(upload_url, files=files, headers=headers)
                    upload_response.raise_for_status()
                    analysis_id = upload_response.json()["data"]["id"]

                report_response = requests.get(VT_REPORT_URL.format(analysis_id), headers=headers)
                report_response.raise_for_status()
                analysis = report_response.json()["data"]["attributes"]
                results = analysis.get("results", {})

            output_lines = []
            for vendor, details in results.items():
                category = details.get("category", "undetected")
                result = details.get("result", "")
                if category != "undetected":
                    output_lines.append(f"{vendor}: {category} - {result}")

            if not output_lines:
                return "No malicious detections found."

            return "\n".join(output_lines)

        except Exception as e:
            return f"Error: {str(e)}"

    def display_result(self, result):
        messagebox.showinfo("Scan Result", result)
        self.label.config(text="Drop a file here")

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = VirusScannerApp(root)

    root.mainloop()
