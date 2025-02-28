import cv2
import numpy as np
import threading
from scapy.all import ARP, Ether, srp, conf
import tkinter as tk

# Настройка Scapy для работы с Npcap/WinPcap
conf.use_pcap = True

NETWORK_RANGE = "10.0.0.1/24"

# Словарь с настройками для разных программ
PROGRAMS = {
    "3303": {
        "IMAGE_PATH": r"C:\Users\Master\Desktop\project\network_scheme.png",
        "DEFAULT_IPS": {
            "D8:43:AE:C5:04:53": "0.0.0.50",
            "D8:43:AE:C5:04:9E": "10.0.0.51",
            "D8:43:AE:C9:3B:4E": "10.0.0.52",
            "D8:43:AE:C9:3B:5A": "10.0.0.53",
            "D8:43:AE:C9:3A:DC": "10.0.0.54",
            "D8:43:AE:C9:3B:5F": "10.0.0.55",
            "D8:43:AE:C5:04:B4": "10.0.0.56",
            "D8:43:AE:C9:3B:4F": "10.0.0.57",
            "D8:43:AE:C9:3B:67": "10.0.0.58",
            "D8:43:AE:C9:3B:37": "10.0.0.59",
            "D8:43:AE:C9:3B:55": "10.0.0.60",
            "D8:43:AE:C9:3D:5C": "10.0.0.61",
            "D8:43:AE:C9:3C:98": "10.0.0.62"
        },
        "DEVICES": {
            "D8:43:AE:C5:04:53": (60, 46),
            "D8:43:AE:C5:04:9E": (165, 110),
            "D8:43:AE:C9:3B:4E": (268, 110),
            "D8:43:AE:C9:3B:5A": (370, 110),
            "D8:43:AE:C9:3A:DC": (470, 110),
            "D8:43:AE:C9:3B:5F": (172, 231),
            "D8:43:AE:C5:04:B4": (275, 229),
            "D8:43:AE:C9:3B:4F": (374, 230),
            "D8:43:AE:C9:3B:67": (473, 228),
            "D8:43:AE:C9:3B:37": (172, 360),
            "D8:43:AE:C9:3B:55": (275, 360),
            "D8:43:AE:C9:3D:5C": (374, 360),
            "D8:43:AE:C9:3C:98": (473, 360)
        }
    },
    "3307": {
        "IMAGE_PATH": r"C:\Users\Master\Desktop\project\network_scheme3307.png",
        "DEFAULT_IPS": {
            "D8:43:AE:C9:3A:BD": "10.0.0.30",
            "D8:43:AE:C5:04:91": "10.0.0.31",
            "D8:43:AE:C9:3B:53": "10.0.0.32",
            "D8:43:AE:C9:3B:06": "10.0.0.33",
            "D8:43:AE:C9:3B:2C": "10.0.0.34",
            "D8:43:AE:C9:3B:56": "10.0.0.35",
            "D8:43:AE:C9:3B:43": "10.0.0.36",
            "D8:43:AE:C5:04:9C": "10.0.0.37",
            "D8:43:AE:C5:04:B2": "10.0.0.38",
            "D8:43:AE:C9:3B:73": "10.0.0.39",
            "D8:43:AE:C9:3B:5E": "10.0.0.40",
            "D8:43:AE:C9:3B:46": "10.0.0.41",
            "D8:43:AE:C5:04:96": "10.0.0.42"
        },
        "DEVICES": {
            "D8:43:AE:C9:3A:BD": (60, 46),
            "D8:43:AE:C5:04:91": (165, 110),
            "D8:43:AE:C9:3B:53": (268, 110),
            "D8:43:AE:C9:3B:06": (370, 110),
            "D8:43:AE:C9:3B:2C": (470, 110),
            "D8:43:AE:C9:3B:56": (172, 231),
            "D8:43:AE:C9:3B:43": (275, 229),
            "D8:43:AE:C5:04:9C": (374, 230),
            "D8:43:AE:C5:04:B2": (473, 228),
            "D8:43:AE:C9:3B:73": (172, 360),
            "D8:43:AE:C9:3B:5E": (275, 360),
            "D8:43:AE:C9:3B:46": (374, 360),
            "D8:43:AE:C5:04:96": (473, 360)
        }
    }
}

def perform_arp_scan(ip_range, devices):
    """Выполняет ARP-сканирование сети и ищет MAC-адреса."""
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=2, verbose=False)[0]
    
    found_devices = {}
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc.upper()
        if mac in devices:
            found_devices[mac] = ip
    return found_devices

def show_image_with_circles(found_devices, devices, default_ips, image_path):
    """Открывает изображение и накладывает круги с IP-адресами."""
    image = cv2.imread(image_path)
    if image is None:
        print("Ошибка: изображение не найдено")
        return
    
    circle_radius = 10  # Увеличенный радиус круга
    colors = {
        "red": (0, 0, 255),  # Устройство не в сети
        "green": (0, 255, 0),  # IP совпадает с заданным
        "yellow": (0, 255, 255)  # IP отличается от заданного
    }
    
    frame = image.copy()
    for mac, (x, y) in devices.items():
        if mac in found_devices:
            ip_address = found_devices[mac]
            default_ip = default_ips.get(mac, "")
            if ip_address == default_ip:
                color = colors["green"]
            else:
                color = colors["yellow"]
        else:
            color = colors["red"]
        
        cv2.circle(frame, (x, y), circle_radius, color, -1)
        
        if mac in found_devices:
            text_position = (x - 20, y - 22)  # Подняли текст выше на 7
            cv2.putText(frame, found_devices[mac], text_position, cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 0, 0), 1, cv2.LINE_AA)
    
    cv2.imshow("Network Map", frame)
    cv2.waitKey(0)
    cv2.destroyAllWindows()

def start_scan(program_key):
    """Запускает сканирование сети и отображает карту."""
    program = PROGRAMS[program_key]
    found_devices = perform_arp_scan(NETWORK_RANGE, program["DEVICES"])
    show_image_with_circles(found_devices, program["DEVICES"], program["DEFAULT_IPS"], program["IMAGE_PATH"])

def on_button_click(program_key):
    """Обработчик клика по кнопке."""
    scan_thread = threading.Thread(target=start_scan, args=(program_key,))
    scan_thread.start()

def create_gui():
    """Создает графический интерфейс с кнопками."""
    root = tk.Tk()
    root.title("Выберите программу")

    button_3303 = tk.Button(root, text="3303", command=lambda: on_button_click("3303"))
    button_3303.pack(padx=20, pady=10)

    button_3307 = tk.Button(root, text="3307", command=lambda: on_button_click("3307"))
    button_3307.pack(padx=20, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()