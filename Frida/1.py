import frida

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if 'Request Data:' in payload:
            # Выводим "Request Data"
            print(payload)
        else:
            # Обработка данных из JavaScript-кода
            print("Data from JavaScript code:", payload)
    else:
        print(message)

# Чтение кода сценария из файла 'script.js' с явным указанием кодировки utf-8
with open('script.js', 'r', encoding='utf-8') as script_file:
    jscode = script_file.read()

# Подключение к процессу WhatsApp
device = frida.get_usb_device()
session = device.attach('WhatsApp')

# Загрузка сценария
script = session.create_script(jscode)
script.on('message', on_message)
script.load()

#0x2FEB70 - WhatsApp/2.23.21.88 Android/13.0.0 Device/Asus-Rog_Phone_7
#0x2FEC10 - WhatsApp/2.23.21.76 Android/13.0.0 Device/Asus-Rog_Phone_7
# Ваш JavaScript-код для Frida
js_code = """
const libwhatsapp_base_adr = Module.findBaseAddress("libwhatsapp.so");
console.log("libwhatsapp.so address => ", libwhatsapp_base_adr);
//0x8E5320 - 2.24.4.76
Interceptor.attach(libwhatsapp_base_adr.add(0x35C174), {
    onEnter: function(args) {
        console.log("called");
    },
    onLeave: function(retval) {
        var str = retval.readCString();
        send(str);//formattedData
        
        /*if (str.indexOf('&e_skey_val=') != -1 || str.indexOf('https://') != -1) {
            // Форматируем URL и параметры и отправляем их в Python-скрипт
            var url = str.split('&')[0];
            var params = str.substring(url.length);
            var formattedData = url + '?' + params;
            send(str);//formattedData
        }*/

        return "1";
    }
});
"""

# Присоединяемся к процессу WhatsApp Business с указанным PID
process = device.attach('WhatsApp')  # Замените на фактический PID вашего процесса frida-ps -U

# Создаем скрипт Frida и добавляем обратный вызов для сообщений
script = process.create_script(js_code)
script.on('message', on_message)

# Запускаем скрипт
script.load()

# Вывод информации о запуске сценария
print('[*] Running CTF')

# Ожидаем завершения
input('[*] Press Enter to exit\n')
