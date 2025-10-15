import base64
import zlib
import re
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Optional
import os # Import os for file handling

# --- CORE DEOBFUSCATION LOGIC ---

def deobfuscate_stage(obfuscated_code: str) -> Optional[str]:
    """
    Extracts the encoded payload from the code, reverses the obfuscation layers, 
    and returns the result.
    """
    # Use regex to find the encoded byte string within the exec((_)(b'...')) pattern
    match = re.search(r"exec\(\(_\)\(b'([a-zA-Z0-9+/=]+)'\)\)", obfuscated_code)
    
    encoded_payload_string = None

    if match:
        encoded_payload_string = match.group(1)
    else:
        # Fallback check for raw encoded bytes if the exec/lambda wrapper is gone
        match_raw = re.search(r"b'([a-zA-Z0-9+/=]+)'", obfuscated_code)
        if match_raw:
             # If we find raw bytes, assume it's the payload for this stage
             encoded_payload_string = match_raw.group(1)
        else:
             return None  # No valid payload found
        
    encoded_data = encoded_payload_string.encode('utf-8')

    try:
        # 1. Reverse the string (the __[::-1] step)
        reversed_data = encoded_data[::-1]

        # 2. Base64 Decode
        b64_decoded = base64.b64decode(reversed_data)

        # 3. Zlib Decompress
        final_payload_bytes = zlib.decompress(b64_decoded)
        final_payload = final_payload_bytes.decode('utf-8', errors='ignore')

        return final_payload

    except Exception:
        # Catch any decoding, decompression, or other runtime errors
        return None

# --- GUI LOGIC ---

def run_deobfuscation(file_path: str, output_text_widget: tk.Text):
    """
    Reads the file, runs the multi-stage deobfuscation loop automatically,
    and prints results to the GUI text widget.
    """
    output_text_widget.delete(1.0, tk.END) # Clear previous results
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            initial_obfuscated_code = f.read().strip()

    except FileNotFoundError:
        messagebox.showerror("Error", f"File not found: {file_path}")
        return
    except Exception as e:
        messagebox.showerror("Error", f"Error reading file: {e}")
        return

    current_code = initial_obfuscated_code
    stage = 1
    
    output_text_widget.insert(tk.END, "--- Analysis Started ---\n")

    while current_code:
        
        # Check if the code still matches the obfuscation pattern
        is_obfuscated_stage = re.search(r"exec\(\(_\)\(b'([a-zA-Z0-9+/=]+)'\)\)", current_code)
        
        if not is_obfuscated_stage:
            # Logic for when the FINAL payload is reached
            final_payload = current_code
            output_text_widget.insert(tk.END, "\n--- FINAL PAYLOAD REACHED ---\n")
            output_text_widget.insert(tk.END, "="*50 + "\n")
            output_text_widget.insert(tk.END, "Final Decoded Code:\n")
            output_text_widget.insert(tk.END, final_payload)
            output_text_widget.insert(tk.END, "\n" + "="*50 + "\n")
            
            # --- NEW LOGIC: SAVE FINAL PAYLOAD TO FILE ---
            try:
                # Define the output file path in the current working directory
                output_file_name = "payload.txt"
                output_file_path = os.path.join(os.getcwd(), output_file_name)
                
                with open(output_file_path, 'w', encoding='utf-8') as outfile:
                    outfile.write(final_payload)
                
                messagebox.showinfo("Success", f"Final payload saved successfully to:\n{output_file_path}")
                output_text_widget.insert(tk.END, f"\n[INFO] Saved final payload to: {output_file_name}\n")
            except Exception as save_e:
                messagebox.showerror("Save Error", f"Failed to save final payload: {save_e}")
                output_text_widget.insert(tk.END, f"\n[ERROR] Failed to save final payload: {save_e}\n")
            # --- END NEW LOGIC ---
            
            break

        output_text_widget.insert(tk.END, f"\n--- Starting Deobfuscation for Stage {stage} ---\n")
        
        # Attempt to deobfuscate the current stage
        deobfuscated_output = deobfuscate_stage(current_code)
        
        if deobfuscated_output is None:
            output_text_widget.insert(tk.END, "🛑 Deobfuscation halted. No more valid encoded payloads found or an error occurred.\n")
            break
        
        # Display the result
        output_text_widget.insert(tk.END, f"✅ Stage {stage} successful. Payload Length: {len(deobfuscated_output)} bytes.\n")
        output_text_widget.insert(tk.END, "="*50 + "\n")
        output_text_widget.insert(tk.END, f"--- STAGE {stage} PAYLOAD ---\n")
        output_text_widget.insert(tk.END, deobfuscated_output + "\n")
        output_text_widget.insert(tk.END, "="*50 + "\n")

        # Set the output as the input for the next stage
        current_code = deobfuscated_output
        stage += 1


class DeobfuscatorApp:
    def __init__(self, master):
        self.master = master
        master.title("Python Multi-Stage Deobfuscator")
        
        self.file_path = tk.StringVar()
        self.setup_widgets()

    def setup_widgets(self):
        # 1. File Selection Frame
        frame_file = tk.Frame(self.master, padx=10, pady=10)
        frame_file.pack(fill='x')

        tk.Label(frame_file, text="Selected File:").pack(side=tk.LEFT)
        
        tk.Entry(frame_file, textvariable=self.file_path, width=60, state='readonly').pack(side=tk.LEFT, padx=5)

        tk.Button(frame_file, text="Browse File 📂", command=self.browse_file).pack(side=tk.LEFT, padx=5)
        
        tk.Button(frame_file, text="Deobfuscate ▶️", command=self.process_file, bg='#006400', fg='white').pack(side=tk.LEFT, padx=10)

        # 2. Output Frame
        frame_output = tk.Frame(self.master, padx=10, pady=10)
        frame_output.pack(fill='both', expand=True)

        tk.Label(frame_output, text="Deobfuscation Output:").pack(anchor='w')
        
        # Text widget for output with scrollbar
        scrollbar = tk.Scrollbar(frame_output)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Using a dark theme for code display
        self.output_text = tk.Text(frame_output, wrap=tk.WORD, height=30, width=80, yscrollcommand=scrollbar.set, bg='#282c34', fg='#61dafb', font=("Consolas", 10))
        self.output_text.pack(fill='both', expand=True)
        
        scrollbar.config(command=self.output_text.yview)

    def browse_file(self):
        """Opens the file dialog and updates the file_path variable."""
        filename = filedialog.askopenfilename(
            title="Select Obfuscated Code File",
            filetypes=[("Text/Python files", "*.txt *.py"), ("All files", "*.*")]
        )
        if filename:
            self.file_path.set(filename)

    def process_file(self):
        """Starts the deobfuscation process with the selected file."""
        if not self.file_path.get():
            messagebox.showwarning("Warning", "Please select a file first.")
            return

        run_deobfuscation(self.file_path.get(), self.output_text)


if __name__ == "__main__":
    root = tk.Tk()
    app = DeobfuscatorApp(root)
    root.mainloop()