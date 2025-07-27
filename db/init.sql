-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Servidor: 192.168.54.120
-- Tiempo de generación: 27-07-2025 a las 01:29:09
-- Versión del servidor: 8.0.36
-- Versión de PHP: 8.2.29

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `etec_cerraduras`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `admins`
--

CREATE TABLE `admins` (
  `id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `hashed_password` varchar(255) NOT NULL,
  `creado_en` datetime DEFAULT CURRENT_TIMESTAMP,
  `role` varchar(50) DEFAULT 'admin'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Volcado de datos para la tabla `admins`
--

INSERT INTO `admins` (`id`, `username`, `hashed_password`, `creado_en`, `role`) VALUES
(1, 'tincho', '$2b$12$FfPI.R/tQoB2.MUhwGlOUuVv4NtVe2wUBShvlWY1pEFMGvlqRI8CK', '2025-07-03 23:26:24', 'admin');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `laboratorios`
--

CREATE TABLE `laboratorios` (
  `id` int NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `topic_mqtt` varchar(150) NOT NULL,
  `creado_en` datetime DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Volcado de datos para la tabla `laboratorios`
--

INSERT INTO `laboratorios` (`id`, `nombre`, `topic_mqtt`, `creado_en`) VALUES
(3, 'Laboratorio de prueba', 'lab1elec', '2025-07-26 23:33:04');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `registros_acceso`
--

CREATE TABLE `registros_acceso` (
  `id` int NOT NULL,
  `laboratorio_id` varchar(255) DEFAULT NULL,
  `tipo_acceso` varchar(100) NOT NULL,
  `usuario_admin` varchar(50) DEFAULT NULL,
  `uuid_rfid` varchar(100) DEFAULT NULL,
  `resultado` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `creado_en` datetime DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Volcado de datos para la tabla `registros_acceso`
--


-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuarios_rfid`
--

CREATE TABLE `usuarios_rfid` (
  `id` int NOT NULL,
  `uuid` varchar(100) NOT NULL,
  `nombre_persona` varchar(100) NOT NULL,
  `autorizado` tinyint(1) DEFAULT '1',
  `hora_desde` time DEFAULT NULL,
  `hora_hasta` time DEFAULT NULL,
  `creado_en` datetime DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Volcado de datos para la tabla `usuarios_rfid`
--

INSERT INTO `usuarios_rfid` (`id`, `uuid`, `nombre_persona`, `autorizado`, `hora_desde`, `hora_hasta`, `creado_en`) VALUES
(2, '3a1f4d1e1e1e', 'Hola', 1, '07:45:00', '09:05:00', '2025-07-04 00:37:41'),
(3, '69-80-E7-D5', 'Test', 0, '21:03:00', '23:04:00', '2025-07-27 00:46:36');

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `admins`
--
ALTER TABLE `admins`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indices de la tabla `laboratorios`
--
ALTER TABLE `laboratorios`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `registros_acceso`
--
ALTER TABLE `registros_acceso`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `usuarios_rfid`
--
ALTER TABLE `usuarios_rfid`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uuid` (`uuid`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `admins`
--
ALTER TABLE `admins`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT de la tabla `laboratorios`
--
ALTER TABLE `laboratorios`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT de la tabla `registros_acceso`
--
ALTER TABLE `registros_acceso`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=50;

--
-- AUTO_INCREMENT de la tabla `usuarios_rfid`
--
ALTER TABLE `usuarios_rfid`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
