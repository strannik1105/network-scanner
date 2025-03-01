import socket
import threading
import tkinter as tk
from tkinter import scrolledtext


class PortScanner:
    def __init__(
        self,
        ip: str,
        first_port: int,
        last_port: int,
        result_text: scrolledtext.ScrolledText,
    ):
        self._ip = ip
        self._first_port = first_port
        self._last_port = last_port
        self._result_text = result_text

    def _scan_ports(self):
        """Функция для сканирования портов."""
        self._result_text.delete(1.0, tk.END)
        self._result_text.insert(tk.END, f"Сканирование {self._ip}...")

        open_ports = []
        for port in range(self._first_port, self._last_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Таймаут в 0.5 секунды
            result = sock.connect_ex((self._ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()

        if open_ports:
            self._result_text.insert(
                tk.END, f"\nОткрытые порты: {', '.join(map(str, open_ports))}"
            )
        else:
            self._result_text.insert(
                tk.END, "\nНет открытых портов в указанном диапазоне."
            )

    def start_scan(self):
        """Запуск сканирования в отдельном потоке."""
        scan_thread = threading.Thread(target=self._scan_ports)
        scan_thread.start()


class ScannerForm:
    def __init__(self, ip: str, parent: tk.Tk = None):
        self._ip = ip
        self._parent = parent

    def show(self):
        self._frame = tk.Frame(self._parent)
        self._frame.pack(pady=10)

        tk.Label(self._frame, text="Начальный порт:").grid(row=0, column=0)
        self._start_port_entry = tk.Entry(self._frame)
        self._start_port_entry.grid(row=0, column=1)

        tk.Label(self._frame, text="Конечный порт:").grid(row=1, column=0)
        self._end_port_entry = tk.Entry(self._frame)
        self._end_port_entry.grid(row=1, column=1)

        self._result_text = scrolledtext.ScrolledText(self._parent, width=50, height=10)
        self._result_text.pack(padx=10, pady=10)

        def button_callback():
            # "10.0.0.53"
            scanner = PortScanner(
                self._ip,
                int(self._start_port_entry.get()),
                int(self._end_port_entry.get()),
                self._result_text,
            )
            scanner.start_scan()

        self._scan_button = tk.Button(
            self._parent, text="Сканировать порты", command=button_callback
        )
        self._scan_button.pack(pady=10)


if __name__ == "__main__":
    # Создание GUI
    root = tk.Tk()
    root.title("Сканер портов")

    ScannerForm(root).show()

    root.mainloop()
