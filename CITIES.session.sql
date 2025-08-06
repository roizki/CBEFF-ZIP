CREATE TABLE IF NOT EXISTS customers (
    id INT PRIMARY KEY,
    customer_name VARCHAR(100),
    contact_name VARCHAR(100),
    address VARCHAR(100),
    city VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100)
);

INSERT INTO customers(id, customer_name, contact_name, address, city, postal_code, country) VALUES
(1, 'Alfreds Futterkiste','Maria Anders','Obere Str. 57','Berlin','12209','Germany'),
(2, 'Ana Trujillo Emparedados y helados','Ana Trujillo','Avda. de la Constitución 2222','México D.F.','05021','Mexico'),
(3, 'Antonio Moreno Taquería','Antonio Moreno','Mataderos 2312','México D.F.','05023','Mexico'),
(4, 'Around the Horn','Thomas Hardy','120 Hanover Sq.','London','WA1 1DP','UK'),
(5,'Berglunds snabbköp','Christina Berglund','Berguvsvägen 8','Luleå','S-958 22','Sweden');





