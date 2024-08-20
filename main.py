import datetime
import hashlib
from kivy.lang import Builder
from kivymd.app import MDApp
from kivymd.uix.screen import Screen
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDFlatButton
from kivymd.uix.textfield import MDTextField
from kivymd.uix.pickers import MDDatePicker, MDTimePicker
from kivy.properties import ObjectProperty
import psycopg2
from kivymd.uix.list import ThreeLineListItem
from kivy.metrics import dp
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Database configuration
DB_HOST = "localhost"
DB_NAME = "courteasy2"
DB_USER = "postgres"
DB_PASS = "16"

# Connect to the database
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)
cur = conn.cursor()

# KivyMD Builder String for the UI
kv_string = """
ScreenManager:
    LoginScreen:
    RegisterScreen:
    HomeScreen:
    ProfileScreen:
    HistoryScreen:
    BookingScreen:
    AvailableCourtsScreen:
    ConfirmationScreen:

<LoginScreen>:
    name: 'login'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(48)
        spacing: dp(16)

        AsyncImage:
            source: 'static/CourtEasy.png' 
            size_hint: 1, 0.5  
            allow_stretch: True  
            keep_ratio: True 

        MDLabel:
            text: "Welcome to CourtEasy!"
            halign: 'center'
            font_style: 'H5'
            theme_text_color: 'Primary'
            size_hint_y: None
            height: dp(36)

        MDTextField:
            id: username_field
            hint_text: 'Username'
            helper_text_mode: 'on_focus'
            required: True
            icon_right: 'account'
            icon_right_color: app.theme_cls.primary_color
            size_hint_y: None
            height: dp(48)
        MDTextField:
            id: password_field
            hint_text: 'Password'
            helper_text_mode: 'on_focus'
            required: True
            password: True
            icon_right: 'lock'
            icon_right_color: app.theme_cls.primary_color
            size_hint_y: None
            height: dp(48)
        MDRectangleFlatButton:
            text: 'Login'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: app.login(username_field.text, password_field.text) if username_field.text.strip() and password_field.text.strip() else app.show_empty_fields_alert_login()
            size_hint_y: None
            height: dp(48)
        MDFlatButton:
            text: 'Register'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'register'
            size_hint_y: None
            height: dp(48)

<RegisterScreen>:
    name: 'register'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(48)
        spacing: dp(16)
        MDTextField:
            id: reg_username_field
            hint_text: 'Username'
            helper_text_mode: 'on_focus'
            required: True
            icon_right: 'account'
            icon_right_color: app.theme_cls.primary_color
            size_hint_y: None
            height: dp(48)
        MDTextField:
            id: reg_number_field
            hint_text: 'Phone Number'
            helper_text_mode: 'on_focus'
            required: True
            icon_right: 'number'
            icon_right_color: app.theme_cls.primary_color
            size_hint_y: None
            height: dp(48)
        MDTextField:
            id: reg_password_field
            hint_text: 'Password'
            helper_text_mode: 'on_focus'
            required: True
            password: True
            icon_right: 'lock'
            icon_right_color: app.theme_cls.primary_color
            size_hint_y: None
            height: dp(48)
        MDRectangleFlatButton:
            text: 'Register'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: app.register(reg_username_field.text, reg_number_field.text, reg_password_field.text)
            size_hint_y: None
            height: dp(48)
        MDFlatButton:
            text: 'Back to Login'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'login'
            size_hint_y: None
            height: dp(48)

<HomeScreen>:
    name: 'home'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(48)
        spacing: dp(16)
        MDLabel:
            text: 'Welcome Home!'
            halign: 'center'
            font_style: 'H4'
        MDRectangleFlatButton:
            text: 'View Profile'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'profile'
        MDRectangleFlatButton:
            text: 'Booking'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'booking'
        MDRectangleFlatButton:
            text: 'History'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'history'
        MDRectangleFlatButton:
            text: 'Back to Login'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'login'

<ProfileScreen>:
    name: 'profile'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(48)
        spacing: dp(16)
        MDLabel:
            id: profile_info
            text: ''
            halign: 'center'
        MDRectangleFlatButton:
            text: 'Change Number'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: app.change_number_dialog()
        MDRectangleFlatButton:
            text: 'Change Password'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: app.change_password_dialog()
        MDRectangleFlatButton:
            text: 'Back to Home'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'home'

<HistoryScreen>:
    name: 'history'
    on_pre_enter: app.show_latest_bookings()
    BoxLayout:
        orientation: 'vertical'
        padding: dp(48)
        spacing: dp(16)
        ScrollView:
            MDList:
                id: history_list
        MDRectangleFlatButton:
            text: 'Home'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'home'

<BookingScreen>:
    name: 'booking'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(48)
        spacing: dp(16)
        MDTextField:
            id: date_field
            hint_text: 'Select Date'
            helper_text_mode: 'on_focus'
            required: True
            icon_right: 'calendar'
            icon_right_color: app.theme_cls.primary_color
            on_focus: app.show_date_picker()
        MDTextField:
            id: time_field
            hint_text: 'Select Time'
            helper_text_mode: 'on_focus'
            required: True
            icon_right: 'clock'
            icon_right_color: app.theme_cls.primary_color
            on_focus: app.show_time_picker()
        MDTextField:
            id: duration_field
            hint_text: 'Duration (Minutes)'
            helper_text_mode: 'on_focus'
            required: True
            input_filter: 'int'
            icon_right: 'clock'
            icon_right_color: app.theme_cls.primary_color
        MDRectangleFlatButton:
            text: 'Book Now'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press:
                app.book_service(date_field.text, time_field.text, duration_field.text)
                root.manager.current = 'available_courts'
        MDRectangleFlatButton:
            text: 'Back to Home'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'home'

<AvailableCourtsScreen>:
    name: 'available_courts'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(48)
        spacing: dp(16)

        AsyncImage:
            source: 'static/layouts/IMID0006.png' 
            size_hint: 1, 0.5  
            allow_stretch: True  
            keep_ratio: True 

        ScrollView:
            MDList:
                id: container
        MDTextField:
            id: court_input
            hint_text: "Enter Court Name"
            helper_text: "e.g., Court 1"
            helper_text_mode: "on_focus"
            mode: "fill"
            multiline: False
        MDRectangleFlatButton:
            text: 'Confirm'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: app.get_running_app().confirm_court()

<ConfirmationScreen>:
    name: 'confirmation'
    BoxLayout:
        orientation: 'vertical'
        padding: dp(48)
        spacing: dp(16)
        MDLabel:
            id: confirmation_info
            text: ''
            halign: 'center'
        MDRectangleFlatButton:
            text: 'Confirm Booking'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: app.confirm_booking()
        MDRectangleFlatButton:
            text: 'Cancel'
            theme_text_color: 'Custom'
            text_color: app.theme_cls.primary_color
            on_press: root.manager.current = 'home'
"""

# Define Screens
class LoginScreen(Screen):
    pass

class RegisterScreen(Screen):
    pass

class HomeScreen(Screen):
    pass

class ProfileScreen(Screen):
    pass

class HistoryScreen(Screen):
    pass

class BookingScreen(Screen):
    pass

class AvailableCourtsScreen(Screen):
    pass

class ConfirmationScreen(Screen):
    pass

AES_KEY = b'courtcourteasyy2'

def encrypt_aes(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt_aes(iv, ct):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return pt

# Main App Class
class MyApp(MDApp):
    date_dialog_opened = False
    time_dialog_opened = False

    def build(self):
        self.theme_cls.theme_style = 'Light'
        self.theme_cls.primary_palette = 'BlueGray'
        return Builder.load_string(kv_string)

    def login(self, customer_username, customer_password):
        print("Customer Ori Password:", customer_password)
        hashed_password = hashlib.sha256(customer_password.encode()).hexdigest()
        print("Customer Hashed Password:", hashed_password)
        cur.execute("SELECT * FROM customer WHERE customer_username = %s AND customer_password = %s", (customer_username, hashed_password))
        user = cur.fetchone()
        if user:
            print("Login successful!")
            user_id = user[1]  
            print("User ID:", user_id)
            
            self.user_id = user_id
            self.show_profile(customer_username)

            self.root.current = 'home'
        else:
            print("Invalid username or password!")

    def show_empty_fields_alert_login(self):
        content_layout = BoxLayout(orientation='vertical', spacing=10)
        
        message_label = Label(text="Please enter both username and password.", size_hint_y=None, height=dp(36), halign='center')
        content_layout.add_widget(message_label)

        ok_button = Button(text='OK', size_hint_y=None, height=dp(48))
        ok_button.bind(on_release=lambda btn: popup.dismiss())
        content_layout.add_widget(ok_button)

        popup = Popup(title="Empty Fields", content=content_layout, size_hint=(None, None), size=(400, 200))
        popup.open()

    def register(self, customer_username, customer_number, customer_password):
        hashed_password = hashlib.sha256(customer_password.encode()).hexdigest()

        customer_number_vector, customer_number_ciphertext = encrypt_aes(customer_number)

        cur.execute("SELECT COALESCE(MAX(c_id), 0) + 1 FROM customer")
        next_id = cur.fetchone()[0]
        customer_id = f"CTID{next_id:04d}"
        customer_last_login = datetime.datetime.now().strftime('%Y/%m/%d %H:%M')
        cur.execute("INSERT INTO customer (customer_id, customer_username, customer_password, customer_number_vector, customer_number_ciphertext, customer_last_login) VALUES (%(customer_id)s, %(customer_username)s, %(customer_password)s, %(customer_number_vector)s, %(customer_number_ciphertext)s, %(customer_last_login)s)", 
                    {'customer_id': customer_id, 'customer_username': customer_username, 'customer_password':hashed_password, 'customer_number_vector':customer_number_vector, 'customer_number_ciphertext':customer_number_ciphertext, 'customer_last_login':customer_last_login})
        conn.commit()
        print('You have successfully registered!')

    def show_profile(self, customer_username):
        cur.execute("SELECT customer_username, customer_number_vector, customer_number_ciphertext, customer_id, customer_last_login FROM customer WHERE customer_username = %s", (customer_username,))
        profile_info = cur.fetchone()

        if profile_info:
            customer_username, customer_number_vector, customer_number_ciphertext, customer_id, customer_last_login = profile_info
            
            decrypted_number = decrypt_aes(customer_number_vector, customer_number_ciphertext)
            
            self.root.get_screen('profile').ids.profile_info.text = (
                f'Username: {customer_username}\n'
                f'Customer ID: {customer_id}\n'
                f'Customer Phone Number: {decrypted_number}\n'
                f'Last Login: {customer_last_login}'
            )
        else:
            self.root.get_screen('profile').ids.profile_info.text = 'Customer not found.'

    def change_number(self, *args):
        new_number = self.dialog.content_cls.text.strip() 
        
        if not new_number: 
            self.dialog.dismiss()  
            self.show_empty_fields_alert_number()  
            return
        
        customer_number_vector, customer_number_ciphertext = encrypt_aes(new_number)

        customer_username = self.root.get_screen('profile').ids.profile_info.text.split('\n')[0].split(': ')[1]
        cur.execute("SELECT customer_id FROM customer WHERE customer_username = %s", (customer_username,))
        user_id = cur.fetchone()[0]
        if user_id:
            cur.execute("UPDATE customer SET customer_number_vector = %s, customer_number_ciphertext = %s WHERE customer_id = %s", (customer_number_vector, customer_number_ciphertext, user_id))
            conn.commit()
            self.dialog.dismiss()
            self.show_profile(customer_username)
            print(new_number)
        else:
            print("User ID not found.")

    def change_number_dialog(self):
        self.dialog = MDDialog(
            title="Change Number",
            type="custom",
            content_cls=MDTextField(
                hint_text="Enter your new phone number",
                helper_text="",
                helper_text_mode="on_focus",
                required=True,
            ),
            buttons=[
                MDFlatButton(
                    text="CANCEL", on_release=lambda *args: self.dialog.dismiss()
                ),
                MDFlatButton(
                    text="OK", on_release=self.change_number
                ),
            ],
        )
        self.dialog.open()

    def show_empty_fields_alert_number(self):
        content_layout = BoxLayout(orientation='vertical', spacing=10)
        
        message_label = Label(text="Please enter a new phone number.", size_hint_y=None, height=dp(36), halign='center')
        content_layout.add_widget(message_label)

        ok_button = Button(text='OK', size_hint_y=None, height=dp(48))
        ok_button.bind(on_release=lambda btn: popup.dismiss())
        content_layout.add_widget(ok_button)

        popup = Popup(title="Empty Field", content=content_layout, size_hint=(None, None), size=(400, 200))
        popup.open()

    def change_password_dialog(self):
        password_field = MDTextField(
            hint_text="Enter your new password",
            helper_text="Must be at least 8 characters",
            helper_text_mode="on_focus",
            password=True,
            required=True,
            size_hint_x=None,
            width=300
        )

        self.dialog = MDDialog(
            title="Change Password",
            type="custom",
            content_cls=password_field, 
            size_hint=(0.9, None),
            height=dp(200),
            buttons=[
                MDFlatButton(
                    text="CANCEL",
                    theme_text_color="Custom",
                    text_color=self.theme_cls.primary_color,
                    on_release=self.close_dialog
                ),
                MDFlatButton(
                    text="OK",
                    theme_text_color="Custom",
                    text_color=self.theme_cls.primary_color,
                    on_release=lambda x: self.submit_new_password(password_field.text) if password_field.text.strip() else self.show_empty_password_alert()
                )
            ]
        )

        self.dialog.open()

    def close_dialog(self, instance):
        self.dialog.dismiss()

    def show_empty_password_alert(self):
        content_layout = BoxLayout(orientation='vertical', spacing=10)
        message_label = Label(text="Please enter a new password.", size_hint_y=None, height=dp(36), halign='center')
        content_layout.add_widget(message_label)
        
        ok_button = Button(text='OK', size_hint_y=None, height=dp(48))
        ok_button.bind(on_release=lambda btn: popup.dismiss())
        content_layout.add_widget(ok_button)

        popup = Popup(title="Empty Password", content=content_layout, size_hint=(None, None), size=(400, 200))
        popup.open()

    def submit_new_password(self, password):
        print("Customer Change Password (Ori):", password)
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        print("Customer Change Password (Hashed):", hashed_password)

        cur.execute("UPDATE customer SET customer_password = %s WHERE customer_id = %s", (hashed_password, self.user_id))
        conn.commit()

        print("New password submitted:", password)
        self.close_dialog(None)

    def book_service(self, date, time, duration):
        date_components = date.split('-')
        time_components = time.split(':')

        if not all([date, time, duration]):
            self.show_empty_fields_alert(screen_to_return='booking')
            return

        year, month, day = map(int, date_components)
        hour, minute, second = map(int, time_components)

        start_time = datetime.datetime(year, month, day, hour, minute, second)

        end_time = start_time + datetime.timedelta(minutes=int(duration))

        formatted_start_time = start_time.strftime("%Y-%m-%d %H:%M")
        formatted_end_time = end_time.strftime("%Y-%m-%d %H:%M")

        customer_username = self.root.get_screen('profile').ids.profile_info.text.split('\n')[0].split(': ')[1]
        cur.execute("SELECT customer_id FROM customer WHERE customer_username = %s", (customer_username,))
        user_id = cur.fetchone()[0]

        self.booking_info = {
            'start_time': formatted_start_time,
            'end_time': formatted_end_time,
            'duration': duration,
            'username': customer_username,
            'user_id': user_id,
        }

        cur.execute('''SELECT * FROM court 
                    WHERE c_id NOT IN (
                        SELECT c_id FROM booking 
                        WHERE booking_start_time < %s AND booking_end_time > %s
                    ) AND court_status = %s''', (formatted_end_time, formatted_start_time, 'Open'))
        available_courts = cur.fetchall()

        available_courts_screen = self.root.get_screen('available_courts')
        available_courts_list = available_courts_screen.ids.container
        available_courts_list.clear_widgets()  # Clear previous entries

        for court in available_courts:
            court_name, court_location = court[1], court[2]
            additional_text = "RM"
            Additional_text = "/ Per Hour"
            full_secondary_text = f"{additional_text} {court_location} {Additional_text}"
            court_item = ThreeLineListItem(text=court_name, secondary_text=full_secondary_text)
            available_courts_list.add_widget(court_item)

        self.root.current = 'available_courts'

    def show_empty_fields_alert(self, screen_to_return):
        content_layout = BoxLayout(orientation='vertical', spacing=10)
        message_label = Label(text="Please fill in all fields.", size_hint_y=None, height=dp(36), halign='center')
        content_layout.add_widget(message_label)
        
        ok_button = Button(text='OK', size_hint_y=None, height=dp(48))
        ok_button.bind(on_release=lambda btn: self.dismiss_alert(screen_to_return))
        content_layout.add_widget(ok_button)

        self.alert_popup = Popup(title="Empty Fields", content=content_layout, size_hint=(None, None), size=(400, 200))
        self.alert_popup.open()

    def dismiss_alert(self, screen_to_return):
        self.alert_popup.dismiss()
        self.root.current = screen_to_return

    def confirm_court(self):
        available_courts_screen = self.root.get_screen('available_courts')

        court_name = available_courts_screen.ids.court_input.text

        if not court_name:
            self.show_no_court_selected_alert()
            return

        cur.execute("SELECT count(*) FROM court WHERE court_name = %s", (court_name,))
        court_exists = cur.fetchone()[0]

        if not court_exists:
            self.show_invalid_court_alert()
            return
    
        booking_info = self.booking_info

        cur.execute("SELECT court_price, court_name FROM court WHERE court_name = %s", (court_name,))
        row = cur.fetchone()

        base_price = row[0]
        c_id = row[1]
        duration = int(booking_info["duration"]) 
        start_time = datetime.datetime.strptime(booking_info["start_time"], "%Y-%m-%d %H:%M")

        if duration == 30:
            total_price = base_price / 2
        else:
            total_price = base_price * (duration / 60)

        formatted_total_price = "{:.2f}".format(total_price)
        
        current_time = datetime.datetime.now()
        if start_time < current_time:
            booking_status = 'Ongoing Game'
        else:
            booking_status = 'Coming Game'

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        cur.execute("SELECT COALESCE(MAX(b_id), 0) + 1 FROM booking")
        next_booking_id = cur.fetchone()[0]
        booking_id = f"BKID{next_booking_id:04d}"

        s_time = datetime.datetime.strptime(booking_info["start_time"], "%Y-%m-%d %H:%M")
        e_time = (s_time + datetime.timedelta(minutes=duration)).strftime("%H:%M")  

        game_time = f"{s_time.strftime('%Y-%m-%d %H:%M')} - {e_time}"

        confirmation_screen = self.root.get_screen('confirmation')
        confirmation_screen.ids.confirmation_info.text =    f'Booking By: {booking_info["username"]}\n' \
                                                        f'Booking ID: {booking_id}\n' \
                                                        f'{c_id}\n' \
                                                        f'Booking Date: {now}\n' \
                                                        f'Game Time: {game_time}\n' \
                                                        f'Duration: {booking_info["duration"]} minutes\n' \
                                                        f'Price: RM {formatted_total_price}\n'
        print(booking_info["username"])            
        self.root.current = 'confirmation'
    
    def show_no_court_selected_alert(self):
        content_layout = BoxLayout(orientation='vertical', spacing=10)
        message_label = Label(text="Please select a court.", size_hint_y=None, height=dp(36), halign='center')
        content_layout.add_widget(message_label)
        
        ok_button = Button(text='OK', size_hint_y=None, height=dp(48))
        ok_button.bind(on_release=lambda btn: popup.dismiss())
        content_layout.add_widget(ok_button)

        popup = Popup(title="No Court Selected", content=content_layout, size_hint=(None, None), size=(400, 200))
        popup.open()

    def show_invalid_court_alert(self):
        content_layout = BoxLayout(orientation='vertical', spacing=10)
        message_label = Label(text="The selected court does not exist. Please select again.", size_hint_y=None, height=dp(36), halign='center')
        content_layout.add_widget(message_label)
        
        ok_button = Button(text='OK', size_hint_y=None, height=dp(48))
        ok_button.bind(on_release=lambda btn: popup.dismiss())
        content_layout.add_widget(ok_button)

        popup = Popup(title="Invalid Court", content=content_layout, size_hint=(None, None), size=(400, 200))
        popup.open()

    def confirm_booking(self):
        available_courts_screen = self.root.get_screen('available_courts')

        court_name = available_courts_screen.ids.court_input.text

        booking_info = self.booking_info

        cur.execute("SELECT court_price, court_name FROM court WHERE court_name = %s", (court_name,))
        row = cur.fetchone()

        base_price = row[0]
        c_id = row[1]
        duration = int(booking_info["duration"]) 
        start_time = datetime.datetime.strptime(booking_info["start_time"], "%Y-%m-%d %H:%M")

        if duration == 30:
            total_price = base_price / 2
        else:
            total_price = base_price * (duration / 60)

        formatted_total_price = "{:.2f}".format(total_price)
        
        current_time = datetime.datetime.now()
        if start_time < current_time:
            booking_status = 'Ongoing Game'
        else:
            booking_status = 'Coming Game'

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        cur.execute("SELECT COALESCE(MAX(b_id), 0) + 1 FROM booking")
        next_booking_id = cur.fetchone()[0]
        booking_id = f"BKID{next_booking_id:04d}"

        s_time = datetime.datetime.strptime(booking_info["start_time"], "%Y-%m-%d %H:%M")
        e_time = (s_time + datetime.timedelta(minutes=duration)).strftime("%H:%M")

        game_time = f"{s_time.strftime('%Y-%m-%d %H:%M')} - {e_time}"

        confirmation_screen = self.root.get_screen('confirmation')
        confirmation_screen.ids.confirmation_info.text =    f'Booking By: {booking_info["username"]}\n' \
                                                        f'Booking ID: {booking_id}\n' \
                                                        f'{c_id}\n' \
                                                        f'Booking Date: {now}\n' \
                                                        f'Game Time: {game_time}\n' \
                                                        f'Duration: {booking_info["duration"]} minutes\n' \
                                                        f'Price: RM {formatted_total_price}\n'

        cur.execute("SELECT c_id FROM court WHERE court_name = %s", (c_id,))
        id = cur.fetchone()

        cur.execute("INSERT INTO booking (booking_name, booking_date, booking_start_time, booking_end_time, booking_duration, booking_price, booking_status, c_id, booking_by, booking_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            (booking_info["username"], now, booking_info["start_time"], booking_info["end_time"],
                            booking_info["duration"], formatted_total_price, booking_status, id, booking_info["user_id"], booking_id))
                                                        
        conn.commit() 

        self.root.current = 'confirmation'
        self.root.current = 'history'
        
    def fetch_latest_bookings(self, user_id):
        cur.execute("SELECT * FROM booking WHERE booking_by = %s ORDER BY booking_date DESC LIMIT 5", (user_id,))
        latest_bookings = cur.fetchall()
        print("fetch latest booking")
        print(latest_bookings)
        print(user_id)
        return latest_bookings

    def show_latest_bookings(self):
        history_screen = self.root.get_screen('history')
        history_list = history_screen.ids.history_list
        history_list.clear_widgets()
        
        if hasattr(self, 'user_id'):
            latest_bookings = self.fetch_latest_bookings(self.user_id)
                    
            for booking in latest_bookings:
                if len(booking) >= 11: 
                    booking_id = booking[1]
                    booking_date = booking[3].strftime('%Y-%m-%d %H:%M')
                    start_time = booking[4].strftime('%Y-%m-%d %H:%M')
                    end_time = booking[5].strftime('%H:%M')
                    price = booking[7]  
                    court_id = booking[9]  
                    cur.execute("SELECT court_name FROM court WHERE c_id=%s", (court_id,))
                    court_name = cur.fetchone()[0] 
                    booking_item = ThreeLineListItem(
                        text=f'Booking ID: {booking_id}',
                        secondary_text=f'{court_name}\n Price: RM{price}',
                        tertiary_text=f'Booking Time: {booking_date}\n   Game Date\ Time: {start_time} - {end_time}'
                    )
                    history_list.add_widget(booking_item)
                else:
                    print("Unexpected number of elements in booking tuple:", len(booking))
        else:
            print("User ID not found. Please login first.")


    def show_date_picker(self):
        if not self.date_dialog_opened:
            def set_date(instance, value, *args):
                self.root.get_screen('booking').ids.date_field.text = value.strftime("%Y-%m-%d")
                self.date_dialog_opened = False

            date_dialog = MDDatePicker()
            date_dialog.bind(on_save=set_date, on_dismiss=self.dismiss_date_picker)
            date_dialog.open()
            self.date_dialog_opened = True

    def show_time_picker(self):
        if not self.time_dialog_opened:
            def set_time(instance, value, *args):
                self.root.get_screen('booking').ids.time_field.text = value.strftime("%H:%M:%S")
                self.time_dialog_opened = False

            time_dialog = MDTimePicker()
            time_dialog.bind(time=set_time, on_dismiss=self.dismiss_time_picker)
            time_dialog.open()
            self.time_dialog_opened = True

    def dismiss_date_picker(self, instance):
        self.date_dialog_opened = False

    def dismiss_time_picker(self, instance):
        self.time_dialog_opened = False

if __name__ == '__main__':
    MyApp().run()
