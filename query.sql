CREATE TABLE booking (
    b_id SERIAL PRIMARY KEY,
    booking_id VARCHAR(15) NOT NULL,
    booking_name VARCHAR(255) NOT NULL,
    booking_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    booking_start_time TIMESTAMP NOT NULL,
    booking_end_time TIMESTAMP NOT NULL,
    booking_duration INTEGER NOT NULL,
    booking_price NUMERIC NOT NULL,
    booking_status VARCHAR(255) NOT NULL,
    c_id INTEGER NOT NULL,
    booking_by VARCHAR(10) NOT NULL,
    FOREIGN KEY (c_id) REFERENCES court(c_id)
);

CREATE TABLE admin (
    a_id SERIAL PRIMARY KEY,
    admin_id VARCHAR(15) NOT NULL,
    admin_username VARCHAR(255) NOT NULL,
    admin_email_vector VARCHAR(255) NOT NULL,
    admin_email_ciphertext  VARCHAR(255) NOT NULL,
    admin_password VARCHAR(255) NOT NULL,
    admin_number_vector VARCHAR(255) NOT NULL,
    admin_number_ciphertext  VARCHAR(255) NOT NULL,
    admin_last_login TIMESTAMP NOT NULL
);

CREATE TABLE customer (
    c_id SERIAL PRIMARY KEY,
    customer_id VARCHAR(15) NOT NULL,
    customer_username VARCHAR(255) NOT NULL,   
    customer_password VARCHAR(255) NOT NULL,
    customer_number_vector VARCHAR(255) NOT NULL,
    customer_number_ciphertext  VARCHAR(255) NOT NULL,    
    customer_last_login TIMESTAMP NOT NULL
);

CREATE TABLE court (
    c_id SERIAL PRIMARY KEY,
    court_id VARCHAR(100) NOT NULL,
    court_name VARCHAR(255) NOT NULL,
    court_price VARCHAR(255) NOT NULL,
    court_status VARCHAR(255) NOT NULL,
    court_livestatus VARCHAR(255) NOT NULL
);

CREATE TABLE image (
	i_id serial PRIMARY KEY,
    image_id VARCHAR(100) NOT NULL,
	court_image VARCHAR ( 100 ) NOT NULL
);