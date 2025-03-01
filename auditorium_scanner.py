import cv2
import threading
from scapy.all import ARP, Ether, srp, conf
import tkinter as tk

from port_scanner import ScannerForm

# Настройка Scapy для работы с Npcap/WinPcap
conf.use_pcap = True

NETWORK_RANGE = "10.0.0.1/24"

PROGRAMS = {
    "3303": {
        "IMAGE_PATH": "network_scheme.png",
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
            "D8:43:AE:C9:3C:98": "10.0.0.62",
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
            "D8:43:AE:C9:3C:98": (473, 360),
        },
        "CLICK_AREA": [(347, 94), (399, 128)],
    }
}


class ArpScanner:
    @staticmethod
    def scan(ip_range, devices):
        arp_request = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        result = srp(packet, timeout=2, verbose=False)[0]
        found_devices = {}
        for _, received in result:
            ip = received.psrc
            mac = received.hwsrc.upper()
            if mac in devices:
                found_devices[mac] = ip
        return found_devices


class AuditoriumScannerForm:
    def on_mouse_click(self, event, x, y, flags, param):
        if event == cv2.EVENT_LBUTTONDOWN:
            program = PROGRAMS["3303"]
            (x1, y1), (x2, y2) = program["CLICK_AREA"]
            if x1 <= x <= x2 and y1 <= y <= y2:
                scanner_form = ScannerForm("0.0.0.0")
                scanner_form.show()

    def show_image_with_circles(self, found_devices, devices, default_ips, image_path):
        image = cv2.imread(image_path)
        if image is None:
            print("Ошибка: изображение не найдено")
            return
        cv2.namedWindow("Network Map")
        cv2.setMouseCallback("Network Map", self.on_mouse_click)
        circle_radius = 10
        colors = {"red": (0, 0, 255), "green": (0, 255, 0), "yellow": (0, 255, 255)}
        frame = image.copy()
        for mac, (x, y) in devices.items():
            color = colors["red"]
            if mac in found_devices:
                ip_address = found_devices[mac]
                default_ip = default_ips.get(mac, "")
                color = (
                    colors["green"] if ip_address == default_ip else colors["yellow"]
                )
            cv2.circle(frame, (x, y), circle_radius, color, -1)
            if mac in found_devices:
                cv2.putText(
                    frame,
                    found_devices[mac],
                    (x - 20, y - 22),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.4,
                    (0, 0, 0),
                    1,
                    cv2.LINE_AA,
                )
        while True:
            cv2.imshow("Network Map", frame)
            if cv2.waitKey(1) & 0xFF == 27:
                break
        cv2.destroyAllWindows()

    def show(self):
        root = tk.Tk()
        root.title("Выберите программу")
        tk.Button(
            root,
            text="3303",
            command=lambda: threading.Thread(
                target=self.start_scan, args=("3303",)
            ).start(),
        ).pack(padx=20, pady=10)
        root.mainloop()

    def start_scan(self, program_key):
        program = PROGRAMS[program_key]
        found_devices = ArpScanner.scan(NETWORK_RANGE, program["DEVICES"])
        self.show_image_with_circles(
            found_devices,
            program["DEVICES"],
            program["DEFAULT_IPS"],
            program["IMAGE_PATH"],
        )


def main():
    form = AuditoriumScannerForm()
    form.show()


if __name__ == "__main__":
    main()
