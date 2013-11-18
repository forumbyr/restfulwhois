package com.cnnic.whois.util.validate;

import java.util.Map;

import com.cnnic.whois.util.WhoisUtil;

public class ValidateUtils {

	private boolean isFuzzyQueryType(int typeIndex){
		if(typeIndex == 1 ||typeIndex == 3 ||typeIndex == 9){
			return true;
		}
		return false;
	}

	public static boolean isFuzzyQueryType(String queryType) {
		if("domains".equals(queryType)||"nameservers".equals(queryType)
				||"entities".equals(queryType)){
			return true;
		}
		return false;
	}
	
	public static String convertFuzzyQueryType(String queryType) {
		if("domains".equals(queryType)){
			return "domain";
		}
		if("nameservers".equals(queryType)){
			return "nameserver";
		}
		if("entities".equals(queryType)){
			return "entity";
		}
		return null;
	}
	
	public static boolean validateDomainName(String domainName){
		if (!isCommonInvalidStr(domainName))
			return false;
		if(!domainName.startsWith("xn--") && !verifyNameServer(domainName)){
			return false;
		}
		return true;
	}
	
	/**
	 * Verifying the String parameters
	 * 
	 * @param parm
	 * @return The correct parity returns true, failure to return false
	 */
	public static boolean isCommonInvalidStr(String parm) {
		String strReg = "^[a-zA-Z\\d\\*]{1}([\\w\\-\\.\\_\\*]*)$";

		if (parm.equals("") || parm == null)
			return false;

		return parm.matches(strReg);
	}
	
	/**
	 * Verifying the NameServer parameters
	 * 
	 * @param queryPara
	 * @return The correct parity returns true, failure to return false
	 */
	public static boolean verifyNameServer(String queryPara) {
		if (!isCommonInvalidStr(queryPara))
			return false;
		String fuzzyReg = "^(?!-.)(?!.*?-$)((\\*)?[0-9a-zA-Z][0-9a-zA-Z-]{0,62}(\\*)?\\.)+([0-9a-zA-Z][0-9a-zA-Z-]{0,62}\\*?)?$";
		if (queryPara.matches(fuzzyReg))
			return true;
		return false;
	}
	
	/**
	 * Verifying the IP parameters
	 * 
	 * @param ipStr
	 * @param ipLengthStr
	 * @return The correct parity returns true, failure to return false
	 */
	public static boolean verifyIP(String ipStr, String ipLengthStr) {
		String regex = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\."
				+ "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
				+ "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
				+ "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
		if (ipLengthStr.equals("0")) {
			if (!ipStr.matches(regex) && !isIPv6(ipStr))
				return false;
		} else {
			if (!ipStr.matches(regex))
				return false;
		}
		if (!ipLengthStr.matches("^[0-9]*$"))
			return false;

		return Integer.parseInt(ipLengthStr) >= 0
				&& Integer.parseInt(ipLengthStr) <= 32;
	}
	
	/**
	 * Verifying the IPv6 parameters
	 * 
	 * @param address
	 * @return The correct parity returns true, failure to return false
	 */
	public static boolean isIPv6(String address) {
		boolean result = false;
		String regHex = "(\\p{XDigit}{1,4})";

		String regIPv6Full = "^(" + regHex + ":){7}" + regHex + "$";

		String regIPv6AbWithColon = "^(" + regHex + "(:|::)){0,6}" + regHex
				+ "$";
		String regIPv6AbStartWithDoubleColon = "^(" + "::(" + regHex
				+ ":){0,5}" + regHex + ")$";
		String regIPv6 = "^(" + regIPv6Full + ")|("
				+ regIPv6AbStartWithDoubleColon + ")|(" + regIPv6AbWithColon
				+ ")$";

		if (address.indexOf(":") != -1) {
			if (address.length() <= 39) {
				String addressTemp = address;
				int doubleColon = 0;
				if (address.equals("::"))
					return true;
				while (addressTemp.indexOf("::") != -1) {
					addressTemp = addressTemp
							.substring(addressTemp.indexOf("::") + 2,
									addressTemp.length());
					doubleColon++;
				}
				if (doubleColon <= 1) {
					result = address.matches(regIPv6);
				}
			}
		}
		return result;
	}
	
	/**
	 * transform Long to IP address
	 * @param map
	 * @return
	 */
	public static Map<String, Object> longToIP(Map<String, Object> map) {
		Object ipversion = map.get("IP Version");

		String startHightAddress = map.get("StartHighAddress").toString();
		String startLowAddress = map.get("StartLowAddress").toString();
		String endHighAddress = map.get("EndHighAddress").toString();
		String endLowAddress = map.get("EndLowAddress").toString();

		map.remove("StartHighAddress");
		map.remove("StartLowAddress");
		map.remove("EndHighAddress");
		map.remove("EndLowAddress");
		String startAddress = "";
		String endAddress = "";
		if (ipversion != null) {
			if (ipversion.toString().indexOf("v6") != -1) {
				startAddress = WhoisUtil.ipV6ToString(
						Long.parseLong(startHightAddress),
						Long.parseLong(startLowAddress));
				endAddress = WhoisUtil.ipV6ToString(
						Long.parseLong(endHighAddress),
						Long.parseLong(endLowAddress));
			} else {
				startAddress = WhoisUtil.longtoipV4(Long
						.parseLong(startLowAddress));
				endAddress = WhoisUtil
						.longtoipV4(Long.parseLong(endLowAddress));
			}
			map.put("Start Address", startAddress);
			map.put("End Address", endAddress);
		}
		return map;
	}
	
}
