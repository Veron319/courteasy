import base64
from datetime import datetime, timedelta
import datetime
from hashlib import sha256
import hashlib
import io
import json
import os
from random import choice
from click import DateTime
from flask import Flask, Response, request, send_file, send_from_directory, session, redirect, url_for, render_template, flash, jsonify
from fpdf import FPDF
import psycopg2
import psycopg2.extras
import re 
from werkzeug.security import generate_password_hash, check_password_hash
from flask import flash, render_template, request
from plyer import notification
import urllib.request
import os
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = 'courteasy2'
AES_KEY = b'courtcourteasyy2'

DB_HOST = "localhost"
DB_NAME = "courteasy2"
DB_USER = "postgres"
DB_PASS = "16"
 
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

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

@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'POST' and 'admin_username' in request.form and 'admin_password' in request.form:
        username = request.form['admin_username']
        password = request.form['admin_password']

        cursor.execute('SELECT * FROM admin WHERE admin_username = %s', (username,))
        account = cursor.fetchone()

        #admin_last_login = datetime.now().strftime('%Y/%m/%d %H:%M')

        if account:
            password_rs = account['admin_password']
            if hash_password(password) == password_rs:
                session['loggedin'] = True
                session['admin_id'] = account['admin_id']
                session['admin_username'] = account['admin_username']
                
                #cursor.execute("""UPDATE admin SET admin_last_login=%s WHERE admin_username = %s""", (admin_last_login, username))
                #conn.commit()

                return redirect(url_for('home'))
            else:
                flash('Incorrect username/password')
        else:
            flash('Incorrect username/password')
    return render_template('login.html')

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cursor.execute('SELECT * FROM admin')
    decryptions = cursor.fetchall()

    # List to store decrypted emails and numbers
    decrypted_emails = []
    decrypted_numbers = []

    for decryption in decryptions:
        decrypted_email = decrypt_aes(decryption['admin_email_vector'], decryption['admin_email_ciphertext'])
        decrypted_emails.append(decrypted_email)

        decrypted_number = decrypt_aes(decryption['admin_number_vector'], decryption['admin_number_ciphertext'])
        decrypted_numbers.append(decrypted_number)

    if request.method == 'POST':
        admin_username = request.form.get('admin_username')
        admin_email = request.form.get('admin_email')
        admin_password = request.form.get('admin_password')
        admin_number = request.form.get('admin_number')

        admin_email_vector, admin_email_ciphertext = encrypt_aes(admin_email)
        admin_number_vector, admin_number_ciphertext = encrypt_aes(admin_number)
        
        cursor.execute('SELECT * FROM admin WHERE admin_username = %(admin_username)s ', {'admin_username': admin_username})
        existing_user = cursor.fetchone()

        if existing_user is not None and existing_user['admin_username'] == admin_username:
            flash('Username already exists!')
        elif admin_email in decrypted_emails:
            flash('Email already exists!')
        elif admin_number in decrypted_numbers:
            flash('Phone Number already exists!')
        else:
            cursor.execute("SELECT COALESCE(MAX(a_id), 0) + 1 FROM admin")
            next_id = cursor.fetchone()[0]
            admin_id = f"AMID{next_id:04d}"

            hashed_password = hash_password(admin_password)
            
            admin_last_login = datetime.now().strftime('%Y/%m/%d %H:%M')

            # Insert the new user
            cursor.execute("INSERT INTO admin (admin_id, admin_username, admin_email_vector, admin_email_ciphertext, admin_password, admin_number_vector, admin_number_ciphertext, admin_last_login) VALUES (%(admin_id)s, %(admin_username)s, %(admin_email_vector)s, %(admin_email_ciphertext)s, %(hashed_password)s, %(admin_number_vector)s, %(admin_number_ciphertext)s, %(admin_last_login)s)", 
                           {'admin_id': admin_id, 'admin_username': admin_username, 'admin_email_vector': admin_email_vector, 'admin_email_ciphertext': admin_email_ciphertext, 'hashed_password': hashed_password, 'admin_number_vector': admin_number_vector, 'admin_number_ciphertext': admin_number_ciphertext, 'admin_last_login': admin_last_login})
            conn.commit()
            flash('You have successfully registered!')

    # Show registration form with message (if any)
    return render_template('register.html')
   
@app.route('/logout')
def logout():
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Retrieve admin username from session
        admin_username = session.get('admin_username')

        # Update last login time
        admin_last_login = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("UPDATE admin SET admin_last_login = %s WHERE admin_username = %s", (admin_last_login, admin_username))
        conn.commit()

        # Clear session data
        session.pop('loggedin', None)
        session.pop('admin_id', None)
        session.pop('admin_username', None)

        # Redirect to login page
        return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
def home():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if 'loggedin' in session:
        # Retrieve user selection
        timeframe = request.args.get('timeframe', 'default')  # Default to 'default' if not provided

        # Calculate start and end dates based on the selected timeframe
        if timeframe == 'default':
            start_date = datetime.min.date()  # Use the minimum date available
            end_date = datetime.max.date()    # Use the maximum date available
        elif timeframe == 'today':
            start_date = datetime.now().date()
            end_date = start_date + timedelta(days=1)
        elif timeframe == 'weekly':
            start_date = datetime.now().date() - timedelta(days=datetime.now().weekday())
            end_date = start_date + timedelta(days=7)
        elif timeframe == 'monthly':
            start_date = datetime(datetime.now().year, datetime.now().month, 1).date()
            end_date = datetime(datetime.now().year, datetime.now().month + 1, 1).date()
        elif timeframe == 'yearly':
            start_date = datetime(datetime.now().year, 1, 1).date()
            end_date = datetime(datetime.now().year + 1, 1, 1).date()

        # Query bookings within the selected timeframe
        cursor.execute('SELECT * FROM booking WHERE booking_date >= %s AND booking_date < %s', (start_date, end_date))
        booking = cursor.fetchall()

        noBookingMessage = None  # Default value
        noCourtDataMessage = None

        if not booking:
            noBookingMessage = "No Booking Today"
            noCourtDataMessage = "No Booking Today"

        totalPrice = round(sum(row['booking_price'] for row in booking), 2)
        totalOrder = len(booking)
        avgPrice = round(totalPrice / totalOrder, 2) if totalOrder > 0 else 0

        #Booking
        cursor.execute('''SELECT * FROM booking WHERE booking_date >= %s AND booking_date < %s ORDER BY booking_id DESC LIMIT 5''', (start_date, end_date))
        recentOrder = cursor.fetchall()

        for row in recentOrder:
            row['booking_date'] = row['booking_date'].strftime('%Y/%m/%d %H:%M')
            row['booking_start_time'] = row['booking_start_time'].strftime('%Y/%m/%d %H:%M')
            row['booking_end_time'] = row['booking_end_time'].strftime('%Y/%m/%d %H:%M')   

        #Court
        cursor.execute('''SELECT booking.c_id, court.court_name, COUNT(*) AS count, SUM(booking.booking_price) AS total_price FROM booking 
            JOIN court ON booking.c_id = court.c_id WHERE booking.booking_date >= %s AND booking.booking_date < %s GROUP BY booking.c_id, court.court_name''', (start_date, end_date))
        courtBookingCounts = cursor.fetchall()
        court_names = [row[1] for row in courtBookingCounts]
        booking_counts = [row[2] for row in courtBookingCounts]
        total_prices = [row[3] for row in courtBookingCounts]

        return render_template('home.html', admin_username=session['admin_username'], totalOrder=totalOrder, totalPrice=totalPrice, recentOrder=recentOrder, avgPrice=avgPrice, court_names=court_names, booking_counts=booking_counts, total_prices=total_prices, courtBookingCounts=courtBookingCounts, noBookingMessage=noBookingMessage, noCourtDataMessage=noCourtDataMessage, timeframe=timeframe)
    return redirect(url_for('login'))

@app.route('/about')
def about(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()
      
        return render_template('about.html', account=account, admin_username=session['admin_username'])
    return redirect(url_for('login'))

@app.route('/contactUs')
def contactUs(): 
    return render_template('contactUs.html')

@app.route('/profile')
def profile(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        decrypted_email = decrypt_aes(account['admin_email_vector'], account['admin_email_ciphertext'])
        decrypted_number = decrypt_aes(account['admin_number_vector'], account['admin_number_ciphertext'])

        return render_template('profile.html', account=account, decrypted_email=decrypted_email, decrypted_number=decrypted_number, admin_username=session['admin_username'])
    return redirect(url_for('login'))

@app.route('/editProfile', methods=['GET', 'POST'])
def editProfile(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        decrypted_email = decrypt_aes(account['admin_email_vector'], account['admin_email_ciphertext'])
        decrypted_number = decrypt_aes(account['admin_number_vector'], account['admin_number_ciphertext'])

        if request.method == 'POST': 
            admin_number = request.form['admin_number']
            
            admin_number_vector, admin_number_ciphertext = encrypt_aes(admin_number)

            cursor.execute('SELECT * FROM admin WHERE admin_number_vector = %s AND admin_id != %s', (admin_number_vector, session['admin_id']))
            existing_number = cursor.fetchone()

            if existing_number:
                flash("Number already exists. Please choose a different one.")
                return render_template('editProfile.html', account=account, admin_username=session['admin_username'], decrypted_email=decrypted_email, decrypted_number=decrypted_number)
            else:
                cursor.execute("""UPDATE admin SET admin_number_vector=%s, admin_number_ciphertext=%s WHERE admin_id=%s """, 
                               (admin_number_vector, admin_number_ciphertext, session['admin_id']))
                conn.commit()
                flash("Data Updated Successfully")
                return redirect(url_for('profile'))
                
        return render_template('editProfile.html', account=account, admin_username=session['admin_username'], decrypted_email=decrypted_email, decrypted_number=decrypted_number)
    return redirect(url_for('login'))

@app.route('/changePassword')
def changePassword(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()
        return render_template('changePassword.html', account=account, admin_username=session['admin_username'])
    return redirect(url_for('login')) 

from hashlib import sha256

@app.route('/updatePassword', methods=['GET', 'POST'])
def updatePassword(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()
        
        if request.method == 'POST':
            admin_password = request.form['admin_password']
            admin_new_password = request.form['admin_new_password']
            admin_new_password_again = request.form['admin_new_password_again']
            
            # Retrieve hashed password from the database
            cursor.execute('SELECT admin_password FROM admin WHERE admin_id = %s', [session['admin_id']])
            stored_password = cursor.fetchone()['admin_password']

            # Verify old password
            if not verify_password(admin_password, stored_password):
                flash("Incorrect old password", "error")
                return redirect(url_for('updatePassword'))

            # Verify new password matches the confirmation
            if admin_new_password != admin_new_password_again:
                flash("New password and confirmation do not match", "error")
                return redirect(url_for('updatePassword'))

            # Hash the new password
            hashed_new_password = hash_password(admin_new_password)

            # Update the password in the database
            cursor.execute('UPDATE admin SET admin_password = %s WHERE admin_id = %s', (hashed_new_password, session['admin_id']))
            conn.commit()

            flash("Password updated successfully", "success")
            return redirect(url_for('profile'))
    
        else:
            return render_template('changePassword.html', account=account, admin_username=session['admin_username'])
    
    return redirect(url_for('login'))

def verify_password(input_password, stored_password):
    return hash_password(input_password) == stored_password

def hash_password(password):
    return sha256(password.encode()).hexdigest()

@app.route('/makeBooking', methods=['GET', 'POST'])
def makeBooking():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        cursor.execute("SELECT court_image FROM image ORDER BY image_id DESC LIMIT 1")
        image_record = cursor.fetchone()
        
        if image_record:
            image_filename = image_record[0]
        else:
            image_filename = None

        if request.method == 'POST':
            # Process form data
            booking_by = request.form['booking_by']
            booking_name = request.form['booking_name']
            booking_start_time_str = request.form['booking_start_time']
            booking_start_time = datetime.strptime(booking_start_time_str, '%Y/%m/%d %H:%M')
            booking_duration = int(request.form['booking_duration'])

            # Calculate the end time based on the booking duration
            booking_end_time = booking_start_time + timedelta(minutes=booking_duration)

            # Format booking start time for saving to the database
            formatted_booking_start_time = booking_start_time.strftime('%Y/%m/%d %H:%M')

            # Query available courts based on the selected date and duration
            cursor.execute('''SELECT * FROM court 
                    WHERE c_id NOT IN (
                        SELECT c_id FROM booking 
                        WHERE booking_start_time < %s AND booking_end_time > %s
                    ) AND court_status = %s''', (booking_end_time, booking_start_time, 'Open'))
            court = cursor.fetchall()

            if not court:
                flash("No available courts for the selected time slot or courts are not open")
                return redirect(url_for('makeBooking'))

            return render_template('selectCourtLayout.html', admin_username=session['admin_username'], court=court, booking_by=booking_by, booking_name=booking_name, booking_start_time=formatted_booking_start_time, booking_duration=booking_duration)

        # If it's a GET request, just render the page with all courts
        cursor.execute('''SELECT * FROM court''')
        court = cursor.fetchall()
        cursor.close()

        return render_template('makeBooking.html', account=account, admin_username=session['admin_username'], court=court, image_record=image_record, image_filename=image_filename)
    return redirect(url_for('login'))

@app.route('/latest_image')
def latest_image():
    static_folder = "static/layouts"  # Path to the static/layouts folder
    # List all files in the static/layouts folder
    files = os.listdir(static_folder)
    # Filter only image files (you can adjust this depending on your file types)
    image_files = [file for file in files if file.endswith(('.png', '.jpg', '.jpeg', '.gif'))]
    # Sort the image files by modified time (latest first)
    sorted_images = sorted(image_files, key=lambda x: os.path.getmtime(os.path.join(static_folder, x)), reverse=True)
    if sorted_images:
        latest_image_filename = sorted_images[0]
        return send_from_directory(static_folder, latest_image_filename)
    else:
        return 'No images found in the static/layouts folder'

@app.route('/createBooking', methods=['POST'])
def createBooking():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        if request.method == 'POST':
            booking_name = request.form['booking_name']
            booking_by = request.form['booking_by']
            current_datetime = datetime.now().strftime('%Y/%m/%d %H:%M')
            booking_start_time_str = request.form['booking_start_time']
            booking_start_time = datetime.strptime(booking_start_time_str, '%Y/%m/%d %H:%M')
            booking_duration = int(request.form['booking_duration'])
            booking_end_time = booking_start_time + timedelta(minutes=booking_duration)
            booking_court = request.form['booking_court']

            # Get base price of the selected court
            cursor.execute("SELECT court_price FROM court WHERE c_id = %s", (booking_court,))
            row = cursor.fetchone()
            base_price = row['court_price']

            # Calculate total price based on booking duration
            if booking_duration == 30:
                total_price = base_price / 2
            else:
                total_price = base_price * (booking_duration / 60)

            # Format booking start time for saving to the database
            formatted_booking_start_time = booking_start_time.strftime('%Y/%m/%d %H:%M')

            # Check for existing bookings for the selected court and time slot
            cursor.execute("SELECT booking_status FROM booking WHERE booking_start_time < %s AND booking_end_time > %s AND c_id = %s",
                        (booking_end_time, booking_start_time, booking_court))
            existing_booking = cursor.fetchone()

            if existing_booking:
                flash("Court already booked for this time slot")
            else:
                # Determine booking status
                current_time = datetime.now()
                if booking_start_time < current_time:
                    booking_status = 'Ongoing Game'
                else:
                    booking_status = 'Coming Game'
                
                # Generate booking_id
                cursor.execute("SELECT COALESCE(MAX(b_id), 0) + 1 FROM booking")
                next_booking_id = cursor.fetchone()[0]
                booking_id = f"BKID{next_booking_id:04d}"

                # Insert booking into database
                cursor.execute("INSERT INTO booking (booking_name, booking_date, booking_start_time, booking_end_time, booking_duration, booking_price, booking_status, c_id, booking_by, booking_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            (booking_name, current_datetime, formatted_booking_start_time, booking_end_time, booking_duration, total_price, booking_status, booking_court, booking_by, booking_id))
                
                cursor.execute("SELECT court_name FROM court WHERE c_id=%s", (booking_court,))
                court_name_result = cursor.fetchall()

                if court_name_result:
                    court_name = court_name_result[0][0]
                    notification.notify(
                        title="New Booking Created",
                        message=f"Booking Name: {booking_name}\nCourt: {court_name}\nStart Time: {formatted_booking_start_time}\nDuration: {booking_duration} minutes",
                        timeout=10
                    )
                else:
                    pass
                conn.commit()
                flash("Successfully booked")

        cursor.close()

        return render_template('makeBooking.html', account=account, admin_username=session['admin_username'])
    return redirect(url_for('login'))

@app.route('/randomCourtBooking', methods=['POST'])
def randomCourtBooking():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        if request.method == 'POST':
            booking_name = request.form['booking_name']
            booking_by = request.form['booking_by']
            current_datetime = datetime.now().strftime('%Y/%m/%d %H:%M')
            booking_start_time_str = request.form['booking_start_time']
            booking_start_time = datetime.strptime(booking_start_time_str, '%Y/%m/%d %H:%M')
            booking_duration = int(request.form['booking_duration'])
            booking_end_time = booking_start_time + timedelta(minutes=booking_duration)

            # Query courts that are available and open
            cursor.execute('''SELECT * FROM court 
                                WHERE c_id NOT IN (
                                    SELECT c_id FROM booking 
                                    WHERE booking_start_time < %s AND booking_end_time > %s
                                ) AND court_status = %s''', (booking_end_time, booking_start_time, 'Open'))
            available_courts = cursor.fetchall()

            if available_courts:
                # Randomly select a court from the available ones
                booking_court = choice(available_courts)['c_id']

                # Get base price of the selected court
                cursor.execute("SELECT court_price FROM court WHERE c_id = %s", (booking_court,))
                row = cursor.fetchone()
                base_price = row['court_price']

                # Calculate total price based on booking duration
                if booking_duration == 30:
                    total_price = base_price / 2
                else:
                    total_price = base_price * (booking_duration / 60)

                # Format booking start time for saving to the database
                formatted_booking_start_time = booking_start_time.strftime('%Y/%m/%d %H:%M')

                # Determine booking status
                current_time = datetime.now()
                if booking_start_time < current_time:
                    booking_status = 'Ongoing Game'
                else:
                    booking_status = 'Coming Game'
                
                # Generate booking_id
                cursor.execute("SELECT COALESCE(MAX(b_id), 0) + 1 FROM booking")
                next_booking_id = cursor.fetchone()[0]
                booking_id = f"BKID{next_booking_id:04d}"

                # Insert booking into database
                cursor.execute("INSERT INTO booking (booking_name, booking_date, booking_start_time, booking_end_time, booking_duration, booking_price, booking_status, c_id, booking_by, booking_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            (booking_name, current_datetime, formatted_booking_start_time, booking_end_time, booking_duration, total_price, booking_status, booking_court, booking_by, booking_id))

                cursor.execute("SELECT court_name FROM court WHERE c_id=%s", (booking_court,))
                court_name_result = cursor.fetchall()

                if court_name_result:
                    court_name = court_name_result[0][0]
                    notification.notify(
                        title="New Booking Created",
                        message=f"Booking Name: {booking_name}\nCourt: {court_name}\nStart Time: {formatted_booking_start_time}\nDuration: {booking_duration} minutes",
                        timeout=10
                    )
                else:
                    pass
                conn.commit()
                flash("Successfully booked")
            else:
                flash("No available courts for the selected time slot or courts are not open")

        cursor.close()

        return render_template('makeBooking.html', account=account, admin_username=session['admin_username'])
    return redirect(url_for('login'))

@app.route('/linkAccBookingMake', methods=['GET', 'POST'])
def linkAccBookingMake():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        cursor.execute('SELECT * FROM customer')
        decryptions = cursor.fetchall()

        decrypted_numbers = {}
        for decryption in decryptions:
            decrypted_number = decrypt_aes(decryption['customer_number_vector'], decryption['customer_number_ciphertext'])
            decrypted_numbers[decrypted_number] = decryption

        print(decrypted_numbers)

        if request.method == 'POST':
            booking_by_phone = request.form['link_account']

            if booking_by_phone in decrypted_numbers:
                customer = decrypted_numbers[booking_by_phone]
                booking_by = customer['customer_id']
                booking_name = customer['customer_username']
                booking_start_time_str = request.form['booking_start_time']
                booking_start_time = datetime.strptime(booking_start_time_str, '%Y/%m/%d %H:%M')
                booking_duration = int(request.form['booking_duration'])
                booking_end_time = booking_start_time + timedelta(minutes=booking_duration)
                formatted_booking_start_time = booking_start_time.strftime('%Y/%m/%d %H:%M')

                cursor.execute('''SELECT * FROM court 
                        WHERE c_id NOT IN (
                            SELECT c_id FROM booking 
                            WHERE booking_start_time < %s AND booking_end_time > %s
                        ) AND court_status = %s''', (booking_end_time, booking_start_time, 'Open'))
                court = cursor.fetchall()

                if not court:
                    flash("No available courts for the selected time slot or courts are not open")
                    return redirect(url_for('linkAccBookingMake'))

                return render_template('selectCourtLayout.html', admin_username=session['admin_username'], court=court, booking_by=booking_by, booking_name=booking_name, booking_start_time=formatted_booking_start_time, booking_duration=booking_duration)
            else:
                flash("Phone Number does not exist")
                return render_template('linkAccBookingMake.html', account=account, admin_username=session['admin_username'])

        cursor.execute('''SELECT * FROM court''')
        court = cursor.fetchall()
        cursor.close()

        return render_template('linkAccBookingMake.html', account=account, admin_username=session['admin_username'], court=court)
    return redirect(url_for('login'))

@app.route('/linkAccBookingCreate', methods=['POST'])
def linkAccBookingCreate():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        if request.method == 'POST':
            booking_name = request.form['booking_name']
            booking_by = request.form['booking_by']
            current_datetime = datetime.now().strftime('%Y/%m/%d %H:%M')
            booking_start_time_str = request.form['booking_start_time']
            booking_start_time = datetime.strptime(booking_start_time_str, '%Y/%m/%d %H:%M')
            booking_duration = int(request.form['booking_duration'])
            booking_end_time = booking_start_time + timedelta(minutes=booking_duration)
            booking_court = request.form['booking_court']

            # Get base price of the selected court
            cursor.execute("SELECT court_price FROM court WHERE c_id = %s", (booking_court,))
            row = cursor.fetchone()
            base_price = row['court_price']

            # Calculate total price based on booking duration
            if booking_duration == 30:
                total_price = base_price / 2
            else:
                total_price = base_price * (booking_duration / 60)

            # Format booking start time for saving to the database
            formatted_booking_start_time = booking_start_time.strftime('%Y/%m/%d %H:%M')

            # Check for existing bookings for the selected court and time slot
            cursor.execute("SELECT booking_status FROM booking WHERE booking_start_time < %s AND booking_end_time > %s AND c_id = %s",
                        (booking_end_time, booking_start_time, booking_court))
            existing_booking = cursor.fetchone()

            if existing_booking:
                flash("Court already booked for this time slot")
            else:
                # Determine booking status
                current_time = datetime.now()
                if booking_start_time < current_time:
                    booking_status = 'Ongoing Game'
                else:
                    booking_status = 'Coming Game'
                
                # Generate booking_id
                cursor.execute("SELECT COALESCE(MAX(b_id), 0) + 1 FROM booking")
                next_booking_id = cursor.fetchone()[0]
                booking_id = f"BKID{next_booking_id:04d}"

                # Insert booking into database
                cursor.execute("INSERT INTO booking (booking_name, booking_date, booking_start_time, booking_end_time, booking_duration, booking_price, booking_status, c_id, booking_by, booking_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            (booking_name, current_datetime, formatted_booking_start_time, booking_end_time, booking_duration, total_price, booking_status, booking_court, booking_by, booking_id))

                # Send notification to admin
                notification.notify(
                    title="New Booking Created",
                    message=f"Booking Name: {booking_name}\nCourt: {booking_court}\nStart Time: {formatted_booking_start_time}\nDuration: {booking_duration} minutes",
                    timeout=10
                )

                conn.commit()
                flash("Successfully booked")

        cursor.close()

        return render_template('linkAccBookingMake.html', account=account, admin_username=session['admin_username'])
    return redirect(url_for('login'))

@app.route('/linkAccBookingRandom', methods=['POST'])
def linkAccBookingRandom():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        cursor.execute('SELECT * FROM customer')
        decryptions = cursor.fetchall()

        decrypted_numbers = {}
        for decryption in decryptions:
            decrypted_number = decrypt_aes(decryption['customer_number_vector'], decryption['customer_number_ciphertext'])
            decrypted_numbers[decrypted_number] = decryption

        print(decrypted_numbers)
        
        if request.method == 'POST':
            booking_by_phone = request.form['link_account']

            if booking_by_phone in decrypted_numbers:
                customer = decrypted_numbers[booking_by_phone]
                booking_by = customer['customer_id']
                booking_name = customer['customer_username']
                current_datetime = datetime.now().strftime('%Y/%m/%d %H:%M')
                booking_start_time_str = request.form['booking_start_time']
                booking_start_time = datetime.strptime(booking_start_time_str, '%Y/%m/%d %H:%M')
                booking_duration = int(request.form['booking_duration'])
                booking_end_time = booking_start_time + timedelta(minutes=booking_duration)
                formatted_booking_start_time = booking_start_time.strftime('%Y/%m/%d %H:%M')

                cursor.execute('''SELECT * FROM court 
                                WHERE c_id NOT IN (
                                    SELECT c_id FROM booking 
                                    WHERE booking_start_time < %s AND booking_end_time > %s
                                ) AND court_status = %s''', (booking_end_time, booking_start_time, 'Open'))
                available_courts = cursor.fetchall()

                if available_courts:
                    # Randomly select a court from the available ones
                    booking_court = choice(available_courts)['c_id']

                    # Get base price of the selected court
                    cursor.execute("SELECT court_price FROM court WHERE c_id = %s", (booking_court,))
                    row = cursor.fetchone()
                    base_price = row['court_price']

                    # Calculate total price based on booking duration
                    if booking_duration == 30:
                        total_price = base_price / 2
                    else:
                        total_price = base_price * (booking_duration / 60)

                    # Determine booking status
                    current_time = datetime.now()
                    if booking_start_time < current_time:
                        booking_status = 'Ongoing Game'
                    else:
                        booking_status = 'Coming Game'
                    
                    # Generate booking_id
                    cursor.execute("SELECT COALESCE(MAX(b_id), 0) + 1 FROM booking")
                    next_booking_id = cursor.fetchone()[0]
                    booking_id = f"BKID{next_booking_id:04d}"

                    # Insert booking into database
                    cursor.execute("INSERT INTO booking (booking_name, booking_date, booking_start_time, booking_end_time, booking_duration, booking_price, booking_status, c_id, booking_by, booking_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                                (booking_name, current_datetime, formatted_booking_start_time, booking_end_time, booking_duration, total_price, booking_status, booking_court, booking_by, booking_id))
                    
                    cursor.execute("SELECT court_name FROM court WHERE c_id=%s", (booking_court,))
                    court_name_result = cursor.fetchall()
                    
                    if court_name_result:
                        court_name = court_name_result[0][0]
                        notification.notify(
                            title="New Booking Created",
                            message=f"Booking Name: {booking_name}\nCourt: {court_name}\nStart Time: {formatted_booking_start_time}\nDuration: {booking_duration} minutes",
                            timeout=10
                        )
                    else:
                        pass
                    conn.commit()
                    flash("Successfully booked")
            else:
                flash("Phone Number does not exist")
                return render_template('linkAccBookingMake.html', account=account, admin_username=session['admin_username'])

        cursor.execute('''SELECT * FROM court''')
        court = cursor.fetchall()
        cursor.close()

        return render_template('linkAccBookingMake.html', account=account, admin_username=session['admin_username'], court=court)
    return redirect(url_for('login'))

@app.route('/booking')
def booking(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('''SELECT * FROM booking''')
    data = cursor.fetchall()

    cursor.execute('''SELECT * FROM court''')
    court = cursor.fetchall()

    for row in data:
        row['booking_date'] = row['booking_date'].strftime('%Y/%m/%d %H:%M')
        row['booking_start_time'] = row['booking_start_time'].strftime('%H:%M')
        row['booking_end_time'] = row['booking_end_time'].strftime('%H:%M')

    cursor.execute('''SELECT * FROM booking''')
    game_date = cursor.fetchall()

    for row in game_date:
        row['booking_start_time'] = row['booking_start_time'].strftime('%Y/%m/%d')

    return render_template('booking.html', admin_username=session['admin_username'], data=data, court=court, game_date=game_date)

@app.route('/viewBooking/<string:booking_id>')
def viewbBooking(booking_id): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("""
        SELECT b.*, c.court_name
        FROM booking b
        INNER JOIN court c ON b.c_id = c.c_id
        WHERE b.b_id = %s
    """, (booking_id,))
    result = cursor.fetchone()

    # Convert datetime objects to formatted strings
    result['booking_date'] = result['booking_date'].strftime('%Y/%m/%d %H:%M')
    result['booking_start_time'] = result['booking_start_time'].strftime('%H:%M')
    result['booking_end_time'] = result['booking_end_time'].strftime('%H:%M')

    cursor.execute("""
        SELECT b.*, c.court_name
        FROM booking b
        INNER JOIN court c ON b.c_id = c.c_id
        WHERE b.b_id = %s
    """, (booking_id,))    
    game_date = cursor.fetchall()

    # Convert booking_start_time to formatted strings
    for row in game_date:
        row['booking_start_time'] = row['booking_start_time'].strftime('%Y/%m/%d')

    return render_template('viewBooking.html', admin_username=session['admin_username'], result=result, game_date=game_date)

@app.route('/downloadBookingReport')
def downloadBookingReport():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("""
        SELECT b.*, c.court_name
        FROM booking b
        INNER JOIN court c ON b.c_id = c.c_id
    """)
    result = cursor.fetchall()

    pdf = FPDF()
    pdf.add_page()
         
    page_width = pdf.w - 2 * pdf.l_margin
         
    pdf.set_font('Times', 'B', 14.0) 
    pdf.cell(page_width, 0.0, 'Booking History', align='C')
    pdf.ln(10)
 
    pdf.set_font('Courier', '', 8)
         
    col_width = page_width / 6 
    
    pdf.ln(1)
         
    th = pdf.font_size
         
    # Table header with Court Name added
    pdf.cell(15, th, 'ID', border=1)
    pdf.cell(30, th, 'Booking Name', border=1)
    pdf.cell(30, th, 'Booking Date', border=1)
    pdf.cell(20, th, 'Game Date', border=1)
    pdf.cell(30, th, 'Game Time', border=1)
    pdf.cell(15, th, 'Duration', border=1)
    pdf.cell(25, th, 'Price', border=1)
    pdf.cell(20, th, 'Court', border=1)
    pdf.ln(th)

    # Table data
    for row in result:
        booking_date = row['booking_date'].strftime('%Y/%m/%d %H:%M')
        booking_start_time = row['booking_start_time'].strftime('%H:%M')
        booking_end_time = row['booking_end_time'].strftime('%H:%M')
        date = row['booking_start_time'].strftime('%Y/%m/%d')

        pdf.cell(15, th, str(row['booking_id']), border=1)
        pdf.cell(30, th, str(row['booking_name']), border=1)
        pdf.cell(30, th, booking_date, border=1)
        pdf.cell(20, th, date, border=1)
        pdf.cell(30, th, f"{booking_start_time} - {booking_end_time}", border=1)
        pdf.cell(15, th, str(row['booking_duration']), border=1)
        pdf.cell(25, th, f'RM {row["booking_price"]:.2f}', border=1)
        pdf.cell(20, th, str(row['court_name']), border=1)
        pdf.ln(th)

    pdf.ln(10)
         
    pdf.set_font('Times', '', 10.0) 
    pdf.cell(page_width, 0.0, '- end of report -', align='C')
         
    return Response(pdf.output(dest='S').encode('latin-1'), mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=bookingList.pdf'})

from datetime import datetime

@app.route('/editBookingPage/<string:b_id>', methods=['GET', 'POST'])
def editBookingPage(b_id):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        cursor.execute('SELECT * FROM booking WHERE b_id = %s', (b_id,))
        booking = cursor.fetchone()

        cursor.execute("SELECT TO_CHAR(booking_start_time, 'YYYY/MM/DD HH24:MI') AS booking_start_time FROM booking WHERE b_id = %s", (b_id,))
        booking_start_time_row = cursor.fetchone()
        booking_start_time = booking_start_time_row['booking_start_time']

        court_status = request.args.get('court_status', 'Open')
        cursor.execute('''SELECT * FROM court WHERE court_status = %s''', (court_status,))
        court = cursor.fetchall()

        cursor.close()

        return render_template('editBookingPage.html', account=account, admin_username=session['admin_username'], booking=booking, court=court, booking_start_time=booking_start_time)
    return redirect(url_for('login'))

@app.route('/editBookingCourtPage', methods=['GET', 'POST'])
def editBookingCourtPage():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        if request.method == 'POST': 
            b_id = request.form.get('b_id')
            booking_by = request.form.get('booking_by')
            booking_name = request.form.get('booking_name')
            booking_start_time_str = request.form.get('booking_start_time')
            booking_start_time = datetime.strptime(booking_start_time_str, '%Y/%m/%d %H:%M')

            booking_duration = int(request.form.get('booking_duration'))
            booking_end_time = booking_start_time + timedelta(minutes=booking_duration)
            
            existing_booking = b_id

            cursor.execute('''SELECT * FROM court 
                  WHERE c_id NOT IN (
                      SELECT c_id FROM booking 
                      WHERE (booking_start_time < %s AND booking_end_time > %s)
                          AND (b_id <> %s)
                  ) AND court_status = %s''', (booking_end_time, booking_start_time, existing_booking, 'Open'))
            court = cursor.fetchall()

            cursor.close()

            return render_template('editBookingCourtPage.html', court=court, booking_by=booking_by, b_id=b_id, booking_name=booking_name, booking_start_time=booking_start_time, booking_duration=booking_duration)

        cursor.execute('''SELECT * FROM court''')
        court = cursor.fetchall()
        cursor.close()

        return render_template('booking.html', account=account, admin_username=session['admin_username'], court=court)
    return redirect(url_for('login'))

@app.route('/editBooking', methods=['GET', 'POST'])
def editBooking():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        account = cursor.fetchone()

        if request.method == 'POST': 
            booking_by = request.form['booking_by']
            b_id = request.form.get('b_id')
            booking_name = request.form.get('booking_name')
            booking_start_time_str = request.form.get('booking_start_time')
            booking_start_time = datetime.strptime(booking_start_time_str, '%Y-%m-%d %H:%M:%S')

            booking_duration = int(request.form['booking_duration'])
            booking_end_time = booking_start_time + timedelta(minutes=booking_duration)
            booking_court = request.form['booking_court']
            
            cursor.execute("SELECT court_price FROM court WHERE c_id = %s", (booking_court,))
            row = cursor.fetchone()
            base_price = row['court_price']

            if booking_duration == 30:
                total_price = round(base_price / 2, 2)
            else:
                total_price = round(base_price * (booking_duration / 60), 2)
            
            cursor.execute("""SELECT b_id, booking_status FROM booking WHERE booking_start_time < %s AND 
                           booking_end_time > %s AND c_id = %s AND b_id != %s""",
               (booking_end_time, booking_start_time, booking_court, b_id))
            existing_booking = cursor.fetchone()
            
            if existing_booking:
                existing_booking_id = existing_booking['b_id']
                if existing_booking_id == b_id:
                    # This is the current booking being edited, so it's okay
                    # to update without any conflict.
                    current_time = datetime.now()
                    if booking_start_time < current_time:
                        booking_status = 'Ongoing Game'
                    else:
                        booking_status = 'Coming Game'
                                
                    cursor.execute("""UPDATE booking SET booking_name=%s, booking_start_time=%s, booking_end_time=%s, booking_duration=%s, booking_price=%s, booking_status=%s, c_id=%s, booking_by=%s WHERE b_id=%s """, (booking_name, booking_start_time, booking_end_time, booking_duration, total_price, booking_status, booking_court, booking_by, b_id))
                    conn.commit()
                    flash("Data Updated Successfully")
                else:
                    flash("Court already booked for this time slot")
            else:
                # No existing booking or the existing booking has the same ID as the current one being edited.
                current_time = datetime.now()
                if booking_start_time < current_time:
                    booking_status = 'Ongoing Game'
                else:
                    booking_status = 'Coming Game'
                                
                cursor.execute("""UPDATE booking SET booking_name=%s, booking_start_time=%s, booking_end_time=%s, booking_duration=%s, booking_price=%s, booking_status=%s, c_id=%s WHERE b_id=%s """, (booking_name, booking_start_time, booking_end_time, booking_duration, total_price, booking_status, booking_court, b_id))
                conn.commit()
                flash("Data Updated Successfully")

            return redirect(url_for('booking'))            
        return render_template('booking.html', account=account, admin_username=session['admin_username'])
    return redirect(url_for('login'))

@app.route('/deleteBooking/<string:booking_id>', methods=['GET'])
def deleteBooking(booking_id):
    cursor = conn.cursor(cursor_factory = psycopg2.extras.DictCursor)

    flash("Booking Has Been Deleted Successfully")
    cursor.execute("DELETE FROM booking WHERE booking_id=%s", (booking_id,))
    conn.commit()

    return redirect(url_for('booking'))

@app.route('/printBooking/<string:booking_id>', methods=['GET'])
def printBooking(booking_id):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("""
        SELECT b.*, c.court_name
        FROM booking b
        INNER JOIN court c ON b.c_id = c.c_id
        WHERE b.b_id = %s
    """, (booking_id,))
    result = cursor.fetchone()

    result['booking_date'] = result['booking_date'].strftime('%Y/%m/%d %H:%M')
    result['booking_start_time'] = result['booking_start_time'].strftime('%H:%M')
    result['booking_end_time'] = result['booking_end_time'].strftime('%H:%M')

    cursor.execute("""
        SELECT b.*, c.court_name
        FROM booking b
        INNER JOIN court c ON b.c_id = c.c_id
        WHERE b.b_id = %s
    """, (booking_id,))    
    game_date = cursor.fetchall()

    for row in game_date:
        row['booking_start_time'] = row['booking_start_time'].strftime('%Y/%m/%d')

    if not result:
        return "Booking not found", 404

    # Create PDF instance
    pdf = FPDF()
    pdf.add_page()

    # Set up page width
    page_width = pdf.w - 2 * pdf.l_margin

    # Company Name and Address
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(page_width, 10, 'CourtEasy', 0, 1, 'C')
    pdf.cell(0, 10, 'Bukit Beruang, Malacca', 0, 1, 'C')
    pdf.ln(10)

    # Title
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(page_width, 10, 'Booking Receipt', 0, 1, 'C')
    pdf.ln(10)

    # Booking Details
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f'Booking ID: {result["booking_id"]}', 0, 1)
    pdf.cell(0, 10, f'Book By: {result["booking_by"]}', 0, 1)
    pdf.cell(0, 10, f'Booking Name: {result["booking_name"]}', 0, 1)
    pdf.cell(0, 10, f'Booking Date: {result["booking_date"]}', 0, 1)
    pdf.cell(0, 10, f'Game Date: {row["booking_start_time"]}', 0, 1)
    pdf.cell(0, 10, f'Game Time: {result["booking_start_time"]} - {result["booking_end_time"]}', 0, 1)
    pdf.ln(10)

     # Table header
    col_width = page_width / 4
    th = pdf.font_size
    pdf.cell(col_width, th, 'Court Name', border=1)
    pdf.cell(col_width, th, 'Booking Duration', border=1)
    pdf.cell(col_width, th, 'Total Booking Price', border=1)
    pdf.ln(th)

    # Table data
    pdf.cell(col_width, th, str(result["court_name"]), border=1)
    pdf.cell(col_width, th, str(result["booking_duration"]) + ' Min', border=1)
    pdf.cell(col_width, th, 'RM {:.2f}'.format(result["booking_price"]), border=1)
    pdf.ln(10)

    # Footer
    pdf.set_font('Arial', 'I', 10)
    pdf.cell(page_width, 0, '- End of Receipt -', 0, 1, 'C')

    # Set filename as booking_id and booking_name
    filename = f'{result["booking_id"]}_{result["booking_name"]}.pdf'

    # Return the PDF as response with dynamic filename
    return Response(pdf.output(dest='S').encode('latin-1'), mimetype='application/pdf', headers={'Content-Disposition': f'attachment;filename={filename}'})

@app.route('/rencentBooking')
def rencentBooking(): 
    sevenDaysAgo = datetime.now() - timedelta(days=7)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('''SELECT * FROM booking WHERE booking_date >= %s''', (sevenDaysAgo,))
    data = cursor.fetchall()

    cursor.execute('''SELECT * FROM court''')
    court = cursor.fetchall()

    for row in data:
        row['booking_date'] = row['booking_date'].strftime('%Y/%m/%d %H:%M')
        row['booking_start_time'] = row['booking_start_time'].strftime('%H:%M')
        row['booking_end_time'] = row['booking_end_time'].strftime('%H:%M')

    cursor.execute('''SELECT * FROM booking''')
    game_date = cursor.fetchall()
    for row in game_date:
        row['booking_start_time'] = row['booking_start_time'].strftime('%Y/%m/%d')
    
    return render_template('rencentBooking.html', admin_username=session['admin_username'], data=data, court=court, game_date=game_date)

@app.route('/court')
def court(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
   
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        admin = cursor.fetchone()

        cursor.execute('''SELECT * FROM court''')
        data = cursor.fetchall()

        return render_template('court.html', admin_username=session['admin_username'], admin=admin, data=data)
    return redirect(url_for('login'))

@app.route('/createCourt', methods=['POST'])
def createCourt():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == "POST":
        court_name = request.form['court_name']
        court_price = request.form['court_price']
        court_status = request.form['court_status']

        # Validate court price
        try:
            court_price_value = float(court_price)
            if court_price_value < 0:
                flash("Court price cannot be negative.")
                return redirect(url_for('court'))
        except ValueError:
            flash("Invalid price. Please enter a valid number.")
            return redirect(url_for('court'))

        # Check if court name already exists
        cursor.execute("SELECT EXISTS(SELECT 1 FROM court WHERE court_name = %s)", (court_name,))
        court_exists = cursor.fetchone()[0]

        if court_exists:
            flash("Court name already exists")
            return redirect(url_for('court'))
        else:
            try:
                # Generate court_id
                cursor.execute("SELECT COALESCE(MAX(c_id), 0) + 1 FROM court")
                next_court_id = cursor.fetchone()[0]
                court_id = f"COURT{next_court_id:04d}"

                # Insert new court data into the database
                cursor.execute("INSERT INTO court (court_name, court_price, court_status, court_id) VALUES (%s, %s, %s, %s)",
                               (court_name, court_price, court_status, court_id))
                conn.commit()

                flash("Data inserted successfully")
                return redirect(url_for('court'))
            except Exception as e:
                conn.rollback()
                flash(f"Error: {str(e)}")
                return redirect(url_for('court'))
            finally:
                cursor.close()

    return redirect(url_for('court'))

from datetime import date
@app.route('/updateCourt', methods=['POST'])
def updateCourt():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'POST':
        c_id = request.form['court_id']
        court_name = request.form['court_name']
        court_price = request.form['court_price']
        court_status = request.form['court_status']
        
        # Check if the court price is negative
        try:
            court_price_value = float(court_price)
            if court_price_value < 0:
                flash("Court price cannot be negative.")
                return redirect(url_for('court'))
        except ValueError:
            flash("Invalid price. Please enter a valid number.")
            return redirect(url_for('court'))
        
        if court_status == "Close":
            current_date = date.today()            
            cursor.execute("""SELECT * FROM booking WHERE c_id = %s AND booking_date >= %s""", (c_id, current_date))
            bookings = cursor.fetchall()

            if bookings:
                flash("Cannot close the court. There are bookings scheduled.")
                return redirect(url_for('court'))
        
        cursor.execute("SELECT EXISTS(SELECT 1 FROM court WHERE court_name = %s AND c_id != %s)", (court_name, c_id))
        court_exists = cursor.fetchone()[0]

        if court_exists:
            flash("Court name already exists")
            return redirect(url_for('court'))
        else:
            try:
                cursor.execute("""UPDATE court SET court_name=%s, court_price=%s, court_status=%s WHERE c_id=%s""",
                               (court_name, court_price, court_status, c_id))
                conn.commit()
                flash("Data Updated Successfully")
                return redirect(url_for('court'))
            except Exception as e:
                conn.rollback()
                flash(f"Error: {str(e)}")
                return redirect(url_for('court'))
            finally:
                cursor.close()

    return redirect(url_for('court'))


@app.route('/courtLayout')
def courtLayout(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
   
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM admin WHERE admin_id = %s', [session['admin_id']])
        admin = cursor.fetchone()

        cursor.execute('''SELECT * FROM image''')
        data = cursor.fetchall()

        return render_template('courtLayout.html', admin_username=session['admin_username'], admin=admin, data=data)
    return redirect(url_for('login'))

UPLOAD_FOLDER = 'static/layouts/'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 500 * 500

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/uploadCourtLayout', methods=['GET', 'POST'])
def uploadCourtLayout():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'POST':
        if 'court_image' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['court_image']
        if file.filename == '':
            flash('No image selected for uploading')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):

            cursor.execute("SELECT COALESCE(MAX(i_id), 0) + 1 FROM image")
            next_image_id = cursor.fetchone()[0]
            image_id = f"IMID{next_image_id:04d}"  

            filename = secure_filename(file.filename)
            filename = f"{image_id}.png"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path) 

            cursor.execute("INSERT INTO image (image_id, court_image) VALUES (%s, %s)", (image_id, filename))
            conn.commit()
            
            flash('Image successfully uploaded and displayed below')
            return render_template('courtLayout.html', filename=filename)
        else:
            flash('Allowed image types are png, jpg, jpeg, gif')
            return redirect(request.url)
    else:
        return render_template('courtLayout.html')

@app.route('/display/<filename>')
def display_image(filename):
    # Redirect to the URL of the static file with the provided filename
    return redirect(url_for('static', filename='layouts/' + filename), code=301)

@app.route('/liveCourt')
def liveCourt(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Fetch court data
    cursor.execute('''SELECT * FROM court''')
    data = cursor.fetchall()

    # Fetch bookings for each court with the current date and time
    current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''SELECT * FROM booking WHERE c_id IN (SELECT DISTINCT c_id FROM booking) 
                    AND booking_start_time <= %s AND booking_end_time >= %s''', (current_datetime, current_datetime))
    time = cursor.fetchall()

    # Update court_livestatus based on data availability for each court
    for court in data:
        cursor.execute('''SELECT COUNT(*) FROM booking WHERE c_id = %s 
                    AND booking_start_time <= %s AND booking_end_time >= %s''', (court['c_id'], current_datetime, current_datetime))
        booking_count = cursor.fetchone()[0]

        if booking_count > 0:
            cursor.execute('''UPDATE court SET court_livestatus = %s WHERE c_id = %s''', ('Ongoing', court['c_id']))
        else:
            cursor.execute('''UPDATE court SET court_livestatus = %s WHERE c_id = %s''', ('Empty', court['c_id']))

    # Update booking status to "Completed" for bookings that have ended
    cursor.execute('''UPDATE booking SET booking_status = %s WHERE booking_end_time <= %s AND booking_status != %s RETURNING booking_id, booking_name''', ('Completed Game', current_datetime, 'Completed Game'))
    completed_bookings = cursor.fetchall()

    # Send notification for completed bookings
    for booking in completed_bookings:
        notification.notify(
            title="Booking Completed",
            message=f"The booking {booking['booking_id']} for {booking['booking_name']} has ended.",
            timeout=10
        )

    # Update booking status to "Ongoing" if the live court status is "Ongoing"
    for court_row in data:
        if court_row['court_livestatus'] == "Ongoing":
            cursor.execute('''UPDATE booking SET booking_status = %s WHERE c_id = %s AND booking_start_time <= %s AND booking_end_time >= %s''', ('Ongoing', court_row['c_id'], current_datetime, current_datetime))

    # Send notification for bookings that have 5 minutes left
    five_minutes_later = (datetime.now() + timedelta(minutes=3)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''SELECT * FROM booking WHERE booking_start_time <= %s AND booking_end_time >= %s AND booking_end_time <= %s AND booking_status != %s AND booking_status != %s''', (current_datetime, current_datetime, five_minutes_later, 'Completed', 'Future Booking'))
    bookings_5_minutes_left = cursor.fetchall()
    for booking in bookings_5_minutes_left:
        notification.notify(
            title="Booking Reminder",
            message=f"The booking {booking['booking_id']} for {booking['booking_name']} is almost end.",
            timeout=10
    )

    conn.commit()

    return render_template('liveCourt.html', admin_username=session['admin_username'], data=data, time=time)

@app.route('/saleChart', methods=['GET', 'POST'])
def saleChart(): 
    if request.method == 'POST':
        selected_date_str = request.form['selected_date']
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
        
        # Calculate start and end dates based on the selected date
        start_date = selected_date - timedelta(days=3)
        end_date = selected_date + timedelta(days=3)
    else:
        # Default to the latest 7 days data if no date is provided
        end_date = datetime.now().date() + timedelta(days=1)
        start_date = end_date - timedelta(days=6)
        
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) 

    # Court based on the booking start day
    cursor.execute('''SELECT booking.c_id, court.court_name, COUNT(*) AS count, SUM(booking.booking_price) AS total_price FROM booking 
            JOIN court ON booking.c_id = court.c_id WHERE booking.booking_start_time >= %s AND booking.booking_end_time < %s GROUP BY booking.c_id, court.court_name''', (start_date, end_date))
    courtBookingCounts = cursor.fetchall()
    print(courtBookingCounts)
    courtIDs = [row[1] for row in courtBookingCounts]
    counts = [row[2] for row in courtBookingCounts]
    
    # Booking Start Count
    cursor.execute('SELECT DATE(booking_start_time) AS booking_start, COUNT(*) AS daily_count FROM booking WHERE booking_start_time BETWEEN %s AND %s GROUP BY booking_start ORDER BY booking_start ASC', (start_date, end_date))
    dailyBookingCounts = cursor.fetchall()
    print(dailyBookingCounts)
    # Generate list of dates within the date range
    date_range = [start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1)]
    
    # Initialize dictionary to store counts for each date
    dailyCounts_dict = {row['booking_start'].strftime('%Y-%m-%d'): row['daily_count'] for row in dailyBookingCounts}
    
    # Create lists for chart data
    dailyStarts = []
    dailyCounts = []
    for date in date_range:
        date_str = date.strftime('%Y-%m-%d')
        dailyStarts.append(date_str)
        dailyCounts.append(dailyCounts_dict.get(date_str, 0))  # If no booking for a day, count is zero
        
    return render_template('saleChart.html', admin_username=session['admin_username'], courtBookingCounts=courtBookingCounts, courtIDs=courtIDs, counts=counts, dailyBookingCounts=dailyBookingCounts, dailyStarts=dailyStarts, dailyCounts=dailyCounts)

@app.route('/courtChart', methods=['GET', 'POST'])
def courtChart(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) 

    # Retrieve user selection of timeframe
    timeframe = request.args.get('timeframe', 'default')

    if timeframe == 'default':
        start_date = datetime(datetime.now().year, datetime.now().month, 1).date()
        end_date = datetime(datetime.now().year, datetime.now().month + 1, 1).date()
    elif timeframe in ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']:
        month_number = datetime.strptime(timeframe, '%b').month
        start_date = datetime(datetime.now().year, month_number, 1).date()
        end_date = datetime(datetime.now().year, month_number + 1, 1).date()
    else:
        start_date = datetime.now().date()
        end_date = start_date + timedelta(days=1)

    # Fetch the count of bookings for each court within the selected timeframe
    cursor.execute('''SELECT c.c_id, c.court_name, COUNT(b.b_id) AS count 
                      FROM court c LEFT JOIN booking b ON c.c_id = b.c_id 
                      WHERE b.booking_start_time >= %s AND b.booking_end_time < %s 
                      GROUP BY c.c_id, c.court_name''', (start_date, end_date))
    usageCourtCount = cursor.fetchall()
    
    # Calculate the total number of bookings
    total_bookings = sum(row['count'] for row in usageCourtCount)
    
    # Extract court IDs, names, and counts
    courtIDs = [row['c_id'] for row in usageCourtCount]
    court_names = [row['court_name'] for row in usageCourtCount]
    counts = [row['count'] for row in usageCourtCount]
    
    # Calculate the percentage of bookings for each court
    percentages = [(count / total_bookings) * 100 if total_bookings != 0 else 0 for count in counts]

    cursor.execute('SELECT * FROM court')
    court = cursor.fetchall()

    cursor.execute(""" SELECT EXTRACT(HOUR FROM booking_start_time)::INTEGER || ':00' AS hour_interval, COUNT(*) AS num_bookings 
                   FROM booking 
                   WHERE booking_start_time >= %s AND booking_end_time < %s 
                   AND CAST(booking_start_time AS TIME) BETWEEN '10:00:00' AND '22:00:00' 
                   GROUP BY EXTRACT(HOUR FROM booking_start_time) 
                   ORDER BY EXTRACT(HOUR FROM booking_start_time) """, (start_date, end_date))

    booking_data = cursor.fetchall()

    # Separate the data into lists of time intervals and corresponding counts
    time_intervals = [row[0] for row in booking_data]
    num_bookings = [row[1] for row in booking_data]

    return render_template('courtChart.html', admin_username=session['admin_username'], timeframe=timeframe, time_intervals=time_intervals, num_bookings=num_bookings, 
                           usageCourtCount=usageCourtCount, court_names=court_names, percentages=percentages, total_bookings=total_bookings, 
                           court=court, courtIDs=courtIDs, counts=counts)

@app.route('/dailyCourtRentalsReport')
def dailyCourtRentalsReport(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) 
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM booking')
        booking = cursor.fetchall()
        totalPrice = round(sum(row['booking_price'] for row in booking), 2)
        totalOrder = len(booking)
        avgPrice = avgPrice = round(totalPrice / totalOrder, 2) if totalOrder > 0 else 0

        cursor.execute('''SELECT booking.c_id, court.court_name, COUNT(*) AS count, SUM(booking.booking_price) AS total_price FROM booking 
            JOIN court ON booking.c_id = court.c_id GROUP BY booking.c_id, court.court_name''')
        courtBookingCounts = cursor.fetchall()
        cursor.execute('SELECT c_id, SUM(booking_price) AS total_price FROM booking GROUP BY c_id')
        priceBookingCounts = cursor.fetchall()
        courtSalesCourtID = [row[0] for row in courtBookingCounts]
        courtSalesTotalSales = [row[1] for row in priceBookingCounts]

        return render_template('dailyCourtRentalsReport.html', admin_username=session['admin_username'], totalOrder=totalOrder, courtBookingCounts=courtBookingCounts, 
                               totalPrice=totalPrice, avgPrice=avgPrice, courtSalesCourtID=courtSalesCourtID, courtSalesTotalSales=courtSalesTotalSales)
    return redirect(url_for('login'))

@app.route('/salesReport', methods=['GET', 'POST'])
def salesReport():
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) 

        if request.method == 'POST':
            selected_first_date_str = request.form['selected_first_date']
            selected_first_date = datetime.strptime(selected_first_date_str, '%Y-%m-%d').date()

            selected_second_date_str = request.form['selected_second_date']
            selected_second_date = datetime.strptime(selected_second_date_str, '%Y-%m-%d').date()
        else:
            selected_second_date = date.today()
            selected_first_date = selected_second_date - timedelta(days=1)
        
        # Query for first day's bookings
        cursor.execute('''
            SELECT DATE(booking_date) AS booking_start, COUNT(*) AS daily_count, SUM(booking_price) AS total_price 
            FROM booking WHERE DATE(booking_date) = %s GROUP BY booking_start''', (selected_first_date,))
        firstDay = cursor.fetchall()

        # Query for second day's bookings
        cursor.execute('''
            SELECT DATE(booking_date) AS booking_start, COUNT(*) AS daily_count, SUM(booking_price) AS total_price 
            FROM booking WHERE DATE(booking_date) = %s GROUP BY booking_start''', (selected_second_date,))
        secondDay = cursor.fetchone()

        noBookingMessageToday = None
        noBookingMessageYesterday = None

        # Process first's bookings data
        if not firstDay:
            noBookingMessageToday = "No Bookings"
            firstDay = {'total_price': 0, 'daily_count': 0}
            firstStarts = []
            firstCounts = []
            firstPrices = []
        else:
            firstStarts = [row['booking_start'].strftime('%Y-%m-%d') for row in firstDay]
            firstCounts = [row['daily_count'] if row else 0 for row in firstDay]
            firstPrices = [row['total_price'] if row else 0 for row in firstDay]

        # Process second's bookings data
        if not secondDay:
            noBookingMessageYesterday = "No Bookings"
            secondDay = {'total_price': 0, 'daily_count': 0}
            secondStarts = []
            secondCounts = []
            secondPrices = []
        else:
            secondStarts = [secondDay['booking_start'].strftime('%Y-%m-%d')]
            secondCounts = [secondDay['daily_count']]
            secondPrices = [secondDay['total_price']]

        # Calculate revenue and bookings differences
        firstRevenue = sum(firstPrices)
        secondRevenue = secondDay['total_price']
        revenueDifference = secondRevenue - firstRevenue

        firstBookings = sum(firstCounts)
        secondBookings = secondDay['daily_count']
        bookingsDifference = secondBookings - firstBookings

        return render_template('salesReport.html', admin_username=session['admin_username'], selected_first_date=selected_first_date, selected_second_date=selected_second_date, 
                               firstRevenue=firstRevenue, secondRevenue=secondRevenue,
                               revenueDifference=revenueDifference, firstBookings=firstBookings,
                               secondBookings=secondBookings, bookingsDifference=bookingsDifference,
                               noBookingMessageToday=noBookingMessageToday, noBookingMessageYesterday=noBookingMessageYesterday,
                               firstStarts=firstStarts, firstCounts=firstCounts, firstPrices=firstPrices, secondStarts=secondStarts,
                               secondCounts=secondCounts, secondPrices=secondPrices)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)