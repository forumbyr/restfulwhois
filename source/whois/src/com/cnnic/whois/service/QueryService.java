package com.cnnic.whois.service;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.cnnic.whois.dao.QueryDAO;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.execption.RedirectExecption;
import com.cnnic.whois.util.WhoisProperties;
import com.cnnic.whois.util.WhoisUtil;

public class QueryService {

	private static QueryService queryService = new QueryService();
	private QueryDAO queryDAO = QueryDAO.getQueryDAO();
	public static int MAX_SIZE_FUZZY_QUERY = WhoisProperties.getMaxSizeFuzzyQuery();
	
	private QueryService() {
	}

	/**
	 * Get QueryService objects
	 * 
	 * @return QueryService Object
	 */
	public static QueryService getQueryService() {
		return queryService;
	}

	/**
	 * Ip of the string is converted to type long data, the corresponding query.
	 * 
	 * @param ipInfo
	 * @param ipLength
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 * @throws RedirectExecption
	 */
	public Map<String, Object> queryIP(String ipInfo, int ipLength, String role, String format)
			throws QueryException, RedirectExecption {

		long[] ipLongs = WhoisUtil.parsingIp(ipInfo, ipLength);
		Map<String, Object> map = queryDAO.queryIP(ipLongs[0], ipLongs[1],
				ipLongs[2], ipLongs[3], role, format);
		
		if (map == null) { //If the collection is empty, then go to redirect queries table
			queryDAO.queryIPRedirection(ipLongs[0], ipLongs[1], ipLongs[2],
					ipLongs[3]);
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		if (map.get("$mul$IP") instanceof Object[]) {
			Object[] mapObj = (Object[]) map.get("$mul$IP");
			List<Map<String, Object>> list = new ArrayList<Map<String, Object>>();
			Map<String, Object> mapInfo = new LinkedHashMap<String, Object>();
//			for (Object childMap : mapObj) {
//				list.add(longToIP(((Map<String, Object>) childMap))); //long type data into ip address
//			}
			mapInfo.put("$mul$IP", list.toArray());
			return mapInfo;
		} else {
			return map;
		}
	}

	/**
	 * Long type data into ip address
	 * 
	 * @param map
	 * @return map
	 */
	private Map<String, Object> longToIP(Map<String, Object> map) {
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
			if (ipversion.toString().indexOf("v6") != -1) { //judgment is IPv6 or IPv4
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

	/**
	 * Query as type
	 * 
	 * @param asInfo
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 * @throws RedirectExecption
	 */
	public Map<String, Object> queryAS(int asInfo, String role, String format)
			throws QueryException, RedirectExecption {
		Map<String, Object> map = queryDAO.queryAS(asInfo, role, format);

		if (map == null) {
			getRedirectionURL(WhoisUtil.AUTNUM, Integer.toString(asInfo));
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query nameServer type
	 * 
	 * @param ipInfo
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryNameServer(String ipInfo, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryNameServer(ipInfo, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}
	
	public Map<String, Object> fuzzyQueryNameServer(String nameServer, String role, String format)
			throws QueryException, RedirectExecption {
		Map<String, Object> dnrMap = queryDAO.fuzzyQueryNameServer(nameServer, role, format);
		if (dnrMap == null) {
			String queryType = WhoisUtil.DNRDOMAIN;
			getRedirectionURL(queryType, nameServer);
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}
		Map<String, Object> wholeMap = new LinkedHashMap<String, Object>();
		if (dnrMap != null) {
			wholeMap.putAll(dnrMap);
		}
		return wholeMap;
	}

	public Map<String, Object> fuzzyQueryDomain(String domain, String domainPuny, String role, String format)
			throws QueryException, RedirectExecption {
		Map<String, Object> dnrMap = queryDAO.fuzzyQueryDoamin(domain,domainPuny, role, format);
		if (dnrMap == null) {
			String queryType = WhoisUtil.DNRDOMAIN;
			getRedirectionURL(queryType, domain);
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}
		Map<String, Object> wholeMap = new LinkedHashMap<String, Object>();
		if (dnrMap != null) {
			wholeMap.putAll(dnrMap);
		}
		return wholeMap;
	}
	
	/**
	 * Query doamin type
	 * 
	 * @param ipInfo
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 * @throws RedirectExecption
	 */
	public Map<String, Object> queryDomain(String ipInfo, String role, String format)
			throws QueryException, RedirectExecption {
		Map<String, Object> rirMap = queryDAO.queryRIRDoamin(ipInfo, role, format);
		Map<String, Object> dnrMap = queryDAO.queryDNRDoamin(ipInfo, role, format);

		if (rirMap == null && dnrMap == null) {
			String queryType = WhoisUtil.DNRDOMAIN;

			if (rirMap == null)
				queryType = WhoisUtil.RIRDOMAIN;
			getRedirectionURL(queryType, ipInfo);
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		Map<String, Object> wholeMap = new LinkedHashMap<String, Object>();
		if (rirMap != null) {
			wholeMap.putAll(rirMap);
		}

		if (dnrMap != null) {
			wholeMap.putAll(dnrMap);
		}

		return wholeMap;
	}

	/**
	 * Query entity type
	 * 
	 * @param ipInfo
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 * @throws SQLException 
	 */
	public Map<String, Object> queryEntity(String queryPara, String role, String format)
			throws QueryException, SQLException {
		Map<String, Object> map = queryDAO.queryEntity(queryPara, role, format);
		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}
		return map;
	}
	
	public Map<String, Object> fuzzyQueryEntity(String fuzzyQueryParamName, String queryPara, 
			String role, String format)
			throws QueryException, SQLException {
		Map<String, Object> map = queryDAO.fuzzyQueryEntity(fuzzyQueryParamName,queryPara, role, format);
		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}
		return map;
	}

	/**
	 * Query link type
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryLinks(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryLinks(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query phone type
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryPhones(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryPhones(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query postalAddress type
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryPostalAddress(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryPostalAddress(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query variant type
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryVariants(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryVariants(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}
	
	/**
	 * Query SecureDNS
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> querySecureDNS(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.querySecureDNS(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}
	
	/**
	 * Query DsData
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryDsData(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryDsData(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query KeyData
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryKeyData(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryKeyData(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query delegationKey type
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryDelegationKeys(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryDelegationKeys(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query notice type
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryNotices(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryNotices(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query registrar type
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryRegistrar(String queryPara, String role, boolean isJoinTable, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryRegistrar(queryPara, role, isJoinTable, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query remarks type
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryRemarks(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryRemarks(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * Query events type
	 * 
	 * @param queryPara
	 * @param role
	 * @return map collection
	 * @throws QueryException
	 */
	public Map<String, Object> queryEvents(String queryPara, String role, String format)
			throws QueryException {
		Map<String, Object> map = queryDAO.queryEvents(queryPara, role, format);

		if (map == null) {
			return queryError(WhoisUtil.ERRORCODE, role, format);
		}

		return map;
	}

	/**
	 * The processing Error
	 * 
	 * @return error map collection
	 * @throws QueryException 
	 */
	public Map<String, Object> queryError(String errorCode, String role, String format) throws QueryException {
		Map<String, Object>ErrorMessageMap = null;
		QueryDAO queryDAO = QueryDAO.getQueryDAO();
		ErrorMessageMap = queryDAO.getErrorMessage(errorCode, role, format);
		return ErrorMessageMap;
	}
	
	/**
	 * The processing Help
	 * 
	 * @return help map collection
	 * @throws QueryException 
	 */
	public Map<String, Object> queryHelp(String helpCode, String role, String format) throws QueryException {
		Map<String, Object>helpMap = null;
		QueryDAO queryDAO = QueryDAO.getQueryDAO();
		helpMap = queryDAO.getHelp(helpCode, role, format);
		return helpMap;
	}

	/**
	 * Redirect the forwarding address
	 * 
	 * @param queryType
	 * @param queryPara
	 * @throws QueryException
	 * @throws RedirectExecption
	 */
	private void getRedirectionURL(String queryType, String queryPara)
			throws QueryException, RedirectExecption {
		queryDAO.queryRedirection(queryType, queryPara);
	}
}
