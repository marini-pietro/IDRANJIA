-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Creato il: Apr 18, 2025 alle 15:52
-- Versione del server: 10.4.32-MariaDB
-- Versione PHP: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `idranjia`
--

-- --------------------------------------------------------

--
-- Struttura della tabella `controlli`
--

CREATE TABLE `controlli` (
  `idC` int(11) NOT NULL,
  `data` date NOT NULL,
  `tipo` enum('periodico') NOT NULL COMMENT 'valori ancora da definire in data 18 aprile',
  `esito` tinyint(1) NOT NULL,
  `idI` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `controllooperatore`
--

CREATE TABLE `controllooperatore` (
  `idC` int(11) NOT NULL,
  `CF` char(16) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `foto`
--

CREATE TABLE `foto` (
  `posizione` varchar(255) NOT NULL,
  `data` date NOT NULL COMMENT 'data della foto',
  `idI` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `idranti`
--

CREATE TABLE `idranti` (
  `id` int(11) NOT NULL,
  `stato` enum('utilizzabile','non utilizzabile','tappi presenti','tappi assenti') NOT NULL,
  `latitudine` float NOT NULL COMMENT 'precisione di 1.7m' CHECK (`latitudine` >= -90 and `latitudine` <= 90),
  `longitudine` float NOT NULL COMMENT 'precisione di 1.7m' CHECK (`longitudine` >= -180 and `longitudine` <= 180),
  `comune` varchar(255) NOT NULL,
  `via` varchar(255) NOT NULL,
  `areaGeo` varchar(255) NOT NULL,
  `tipo` enum('a','b') NOT NULL COMMENT 'valori ancora da definire in data 18 aprile',
  `accessibilità` enum('strada stretta','fruibile da autobotte','privato ma accessibile') NOT NULL COMMENT 'valori ancora da definire in data 18 aprile',
  `emailIns` varchar(255) NOT NULL COMMENT 'email dell utente che ha inserito la riga'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `operatori`
--

CREATE TABLE `operatori` (
  `CF` char(16) NOT NULL COMMENT 'i cf possono avere 11 caratteri ma solo per persone non fisiche, suppongo che gli operatori possano solo essere persone fisiche',
  `nome` varchar(255) NOT NULL,
  `cognome` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Struttura della tabella `utenti`
--

CREATE TABLE `utenti` (
  `email` varchar(255) NOT NULL,
  `comune` varchar(255) NOT NULL,
  `nome` varchar(255) NOT NULL,
  `cognome` varchar(255) NOT NULL,
  `admin` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indici per le tabelle scaricate
--

--
-- Indici per le tabelle `controlli`
--
ALTER TABLE `controlli`
  ADD PRIMARY KEY (`idC`),
  ADD KEY `idI` (`idI`);

--
-- Indici per le tabelle `controllooperatore`
--
ALTER TABLE `controllooperatore`
  ADD PRIMARY KEY (`idC`,`CF`),
  ADD KEY `CF` (`CF`);

--
-- Indici per le tabelle `foto`
--
ALTER TABLE `foto`
  ADD PRIMARY KEY (`posizione`),
  ADD KEY `idI` (`idI`);

--
-- Indici per le tabelle `idranti`
--
ALTER TABLE `idranti`
  ADD PRIMARY KEY (`id`),
  ADD KEY `emailIns` (`emailIns`);

--
-- Indici per le tabelle `operatori`
--
ALTER TABLE `operatori`
  ADD PRIMARY KEY (`CF`);

--
-- Indici per le tabelle `utenti`
--
ALTER TABLE `utenti`
  ADD PRIMARY KEY (`email`);

--
-- AUTO_INCREMENT per le tabelle scaricate
--

--
-- AUTO_INCREMENT per la tabella `controlli`
--
ALTER TABLE `controlli`
  MODIFY `idC` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT per la tabella `idranti`
--
ALTER TABLE `idranti`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Limiti per le tabelle scaricate
--

--
-- Limiti per la tabella `controlli`
--
ALTER TABLE `controlli`
  ADD CONSTRAINT `controlli_ibfk_1` FOREIGN KEY (`idI`) REFERENCES `idranti` (`id`);

--
-- Limiti per la tabella `controllooperatore`
--
ALTER TABLE `controllooperatore`
  ADD CONSTRAINT `controllooperatore_ibfk_1` FOREIGN KEY (`idC`) REFERENCES `controlli` (`idC`),
  ADD CONSTRAINT `controllooperatore_ibfk_2` FOREIGN KEY (`CF`) REFERENCES `operatori` (`CF`);

--
-- Limiti per la tabella `foto`
--
ALTER TABLE `foto`
  ADD CONSTRAINT `foto_ibfk_1` FOREIGN KEY (`idI`) REFERENCES `idranti` (`id`);

--
-- Limiti per la tabella `idranti`
--
ALTER TABLE `idranti`
  ADD CONSTRAINT `idranti_ibfk_1` FOREIGN KEY (`emailIns`) REFERENCES `utenti` (`email`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
