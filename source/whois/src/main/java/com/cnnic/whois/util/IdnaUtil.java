package com.cnnic.whois.util;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.vgrs.xcode.idna.Idna;
import com.vgrs.xcode.idna.Punycode;
import com.vgrs.xcode.util.XcodeException;

/**
 * idna util.rfc5890-5894
 * 
 * @author nic
 * 
 */
public class IdnaUtil {
	private static Logger logger = LoggerFactory.getLogger(IdnaUtil.class);
	private static Idna idna = null;

	static {
		try {
			idna = new Idna(new Punycode(), true, true);
		} catch (XcodeException e) {
			logger.error("error :" + e);
		}
	}

	/**
	 * Make a domain name to unicode domain
	 * 
	 * @param ascii
	 *            : ascii domain
	 * @return String : unicode domain
	 * @throws XcodeException
	 */
	public static String toUnicode(String ascii) throws XcodeException {
		if (ascii == null || ascii.isEmpty()) {
			return ascii;
		}
		char[] input = ascii.toCharArray();

		int[] output = idna.domainToUnicode(input);
		StringBuilder sb = new StringBuilder();
		for (int i : output) {
			sb.append((char) i);
		}
		return sb.toString();

	}

	/**
	 * Make a domain name to ascii domain
	 * 
	 * @param ascii
	 *            : unicode domain
	 * @return String : ascii domain
	 * @throws XcodeException
	 */
	public static String toAscii(String unicode) throws XcodeException {
		if (unicode == null || unicode.isEmpty()) {
			return unicode;
		}

		int[] input = new int[unicode.length()];
		int i = 0;
		for (int u : unicode.toCharArray()) {
			input[i++] = u;
		}
		char[] output;
		output = idna.domainToAscii(input);
		return new String(output);
	}

	/**
	 * is Valid IDN,toAscii()and toUnicode() will return ok for xn--55qx5d.[U-LABEL],which should be wrong idn
	 * 
	 * @param domain
	 * @return boolean 
	 */
	public static boolean isValidIdn(String domain) {
		if (domain == null || domain.isEmpty()) {
			return false;
		}
		// convert punycode to unicode
		try {
			return isValidIdnWithException(domain);
		} catch (Exception e) {
			logger.error("error :" + e);
			return false;
		}
	}

	/**
	 * is Valid IDN ,may throw exception
	 * @param domain
	 * @return boolean
	 * @throws XcodeException
	 */
	private static boolean isValidIdnWithException(String domain)
			throws XcodeException {
		String[] labels = domain.split("\\.", -1);
		StringBuilder tmp = new StringBuilder();
		int i = 0;
		// 0: flag of ascii
		int idnType = 0;
		for (String label : labels) {
			if (label == null || label.isEmpty()) {
				return false;
			}
			if (StringUtils.startsWithIgnoreCase(label, "xn--")) {
				tmp.append(toUnicode(label));
				// -1:flag of punycode
				if (idnType > 0) {
					// mixed unicode and punycode
					return false;
				} else if (0 == idnType) {
					idnType = -1;
				}
			} else {
				tmp.append(label);
				for (char ch : label.toCharArray()) {
					// 1:flag of unicode
					if (ch > 0xFF) {
						if (idnType < 0) {
							// mixed punycode & unicode
							return false;
						} else if (0 == idnType) {
							idnType = 1;
						}
						break;
					}
				}
			}
			if (i < labels.length) {
				tmp.append(".");
				i++;
			}
		}
		// convert unicode to ascii
		if (null != toAscii(tmp.toString())) {
			return true;
		}
		return false;
	}
}