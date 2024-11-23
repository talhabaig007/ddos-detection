import tkinter as tk
from tkinter import scrolledtext
class DDOSDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time DDoS Detection Tool")
        self.root.geometry("700x550")  # Adjusted height to accommodate the title

        # GUI Elements
        self.start_button = tk.Button(root, text="Start Detection", command=self.start_detection, bg="green", fg="white", font=("Arial", 12))
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Detection", command=self.stop_detection, bg="red", fg="white", font=("Arial", 12), state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        self.log_label = tk.Label(root, text="Detection Log:", font=("Arial", 12))
        self.log_label.pack()

        self.log_text = scrolledtext.ScrolledText(root, width=80, height=20, font=("Courier", 10))
        self.log_text.pack(pady=10)

        # Title Label
        self.title_label = tk.Label(root, text="Developed by Talha Baig - Hacker", font=("Arial", 12, "bold"), fg="white", bg="black")
        self.title_label.pack(pady=10, side=tk.BOTTOM)

        self.running = False

    def log(self, message):
        """Add a message to the log text box."""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.yview(tk.END)  # Auto-scroll to the bottom

    def reset_counters(self):
        """Reset IP request counters periodically."""
        while self.running:
            time.sleep(RESET_TIME)
            ip_request_count.clear()
            self.log("[INFO] Request counters reset.")

    def detect_ddos(self, pkt):
        """Analyze packets to detect potential DDoS attacks."""
        if IP in pkt:
            src_ip = pkt[IP].src
            ip_request_count[src_ip] += 1

            # Check if any IP exceeds the threshold
            if ip_request_count[src_ip] > REQUEST_THRESHOLD:
                self.log(f"[ALERT] Potential DDoS detected! IP: {src_ip}, Requests: {ip_request_count[src_ip]}")

    def start_sniffing(self):
        """Start packet sniffing."""
        self.log("[INFO] Starting packet sniffing...")
        sniff(filter="ip", prn=self.detect_ddos, store=False, stop_filter=lambda x: not self.running)

    def start_detection(self):
        """Start DDoS detection."""
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Start the counter reset thread
        reset_thread = threading.Thread(target=self.reset_counters)
        reset_thread.daemon = True
        reset_thread.start()

        # Start packet sniffing in a separate thread
        sniff_thread = threading.Thread(target=self.start_sniffing)
        sniff_thread.daemon = True
        sniff_thread.start()

    def stop_detection(self):
        """Stop DDoS detection."""
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log("[INFO] Stopped detection.")

# Main Function
if __name__ == "__main__":
    root = tk.Tk()
    app = DDOSDetectionApp(root)
    root.mainloop()
