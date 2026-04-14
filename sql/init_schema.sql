CREATE TABLE IF NOT EXISTS products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  vendor VARCHAR(100) NOT NULL,
  series VARCHAR(100),
  model VARCHAR(100) NOT NULL,
  UNIQUE KEY uq_product_identity (vendor, series, model)
);

CREATE TABLE IF NOT EXISTS firmware_versions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  product_id INT NOT NULL,
  version_number VARCHAR(50) NOT NULL,
  release_date DATE,
  UNIQUE KEY uq_product_version (product_id, version_number),
  CONSTRAINT fk_fw_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cve_id VARCHAR(50) NOT NULL,
  description TEXT NOT NULL,
  cvss_score DECIMAL(3,1),
  disclosure_date DATE,
  vuln_type VARCHAR(100),
  source_url VARCHAR(500),
  UNIQUE KEY uq_cve_id (cve_id)
);

CREATE TABLE IF NOT EXISTS patches (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cve_id VARCHAR(50) NOT NULL,
  patch_id VARCHAR(50) NOT NULL,
  upgrade_path TEXT,
  UNIQUE KEY uq_patch_identity (cve_id, patch_id),
  CONSTRAINT fk_patch_cve FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS affected_firmware (
  id INT AUTO_INCREMENT PRIMARY KEY,
  vulnerability_id INT NOT NULL,
  firmware_version_id INT NOT NULL,
  UNIQUE KEY uq_affect_relation (vulnerability_id, firmware_version_id),
  CONSTRAINT fk_af_vuln FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  CONSTRAINT fk_af_firmware FOREIGN KEY (firmware_version_id) REFERENCES firmware_versions(id) ON DELETE CASCADE
);
