package edu.usc.softarch.arcade;

public class SecurityDictionary {
	
	// List of Security Frameworks, packages, classes from Java, Spring and Apache Shiro
	
	String [] securityFrameworks = {"java.security", "javax.security", "org.springframework.security","org.springframework.vault","org.apache.shiro"};
	String[] authPackages = {"javax.security.auth","org.springframework.security.authentication","org.springframework.security.access","org.springframework.security.oauth2",
			"org.springframework.security.openid","org.apache.shiro.authc","org.apache.shiro.SecurityUtils","org.apache.shiro.authz","java.security.Permission",
			"java.security.UnresolvedPermission","java.security.Principal","org.apache.shiro.web.filter.authc","org.apache.shiro.web.filter.authc",
			"java.lang.SecurityManager","java.security.Policy", "org.springframework.security.access"};

	String[] cryptoPackages = {"javax.crypto","javax.xml.crypto","org.springframework.security.crypto", "org.apache.shiro.crypto"};
	// need Shiro packages for following:
	String[] sslPackages = {"javax.net.ssl","javax.rmi.ssl","org.springframework.boot.web.server.Ssl"};
	String[] certPackages = {"java.security.cert","javax.security.cert","org.springframework.vault.support.Certificate"};
	String[] rsaPackages = {"java.security.interfaces","org.springframework.cache.interceptor.KeyGenerator","org.springframework.security.rsa"};
	String[] keyPackages = {"java.security.spec","java.security.Provider"};
	// Access Control / Security Policy packages have been added to authPackages
//	String[] accessPackages = {"java.lang.SecurityManager","java.security.Policy", "org.springframework.security.access"};
	
	
//	public String[] getAccessPackages() {
//		return accessPackages;
//	}
	public String[] getSecurityFrameworks() {
		return securityFrameworks;
	}
	public String[] getAuthPackages() {
		return authPackages;
	}
	public String[] getCryptoPackages() {
		return cryptoPackages;
	}
	public String[] getSslPackages() {
		return sslPackages;
	}
	public String[] getCertPackages() {
		return certPackages;
	}
	public String[] getRsaPackages() {
		return rsaPackages;
	}
	public String[] getKeyPackages() {
		return keyPackages;
	}
	
}
