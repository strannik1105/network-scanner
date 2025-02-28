import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

def scan_ports(ip, start_port, end_port, result_text):
    """Функция для сканирования портов."""
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Сканирование {ip}...")
    
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # Таймаут в 0.5 секунды
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        result_text.insert(tk.END, f"\nОткрытые порты: {', '.join(map(str, open_ports))}")
    else:
        result_text.insert(tk.END, "\nНет открытых портов в указанном диапазоне.")

def start_scan():
    """Запуск сканирования в отдельном потоке."""
    ip = "10.0.0.53"
    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
        scan_thread = threading.Thread(target=scan_ports, args=(ip, start_port, end_port, result_text))
        scan_thread.start()
    except ValueError:
        result_text.insert(tk.END, "\nОшибка: Введите корректные номера портов.")

# Создание GUI
root = tk.Tk()
root.title("Сканер портов")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Начальный порт:").grid(row=0, column=0)
start_port_entry = tk.Entry(frame)
start_port_entry.grid(row=0, column=1)

tk.Label(frame, text="Конечный порт:").grid(row=1, column=0)
end_port_entry = tk.Entry(frame)
end_port_entry.grid(row=1, column=1)

scan_button = tk.Button(root, text="Сканировать порты", command=start_scan)
scan_button.pack(pady=10)

result_text = scrolledtext.ScrolledText(root, width=50, height=10)
result_text.pack(padx=10, pady=10)

root.mainloop()