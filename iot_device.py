import random
import time

class IoTDevice:
    def __init__(self):
        self.battery = random.randint(50, 100)

    def get_battery(self):
        self.battery -= random.uniform(0.5, 2.0)
        self.battery = max(self.battery, 0)
        return round(self.battery, 2)

    def get_cpu_usage(self):
        return round(random.uniform(10, 95), 2)

    def get_memory_usage(self):
        return round(random.uniform(20, 90), 2)

    def get_status_label(self, battery, cpu, memory):

        score = 0

        # Battery
        if battery > 70:
            score += 2
        elif battery > 40:
            score += 1

        # CPU (lower is better)
        if cpu < 40:
            score += 2
        elif cpu < 75:
            score += 1

        # Memory (lower usage is better)
        if memory < 50:
            score += 2
        elif memory < 75:
            score += 1

        if score >= 5:
            return "good"
        elif score >= 3:
            return "moderate"
        else:
            return "poor"

    def get_device_status(self):
        battery = self.get_battery()
        cpu = self.get_cpu_usage()
        memory = self.get_memory_usage()

        status = self.get_status_label(battery, cpu, memory)

        return {
            "battery": battery,
            "cpu": cpu,
            "memory": memory,
            "network": status
        }

if __name__ == "__main__":
    device = IoTDevice()

    print("=== IoT DEVICE SIMULATION START ===")
    for _ in range(5):
        print(device.get_device_status())
        time.sleep(2)
    print("=== SIMULATION END ===")