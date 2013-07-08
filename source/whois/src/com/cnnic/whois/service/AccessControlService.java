package com.cnnic.whois.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.cnnic.whois.dao.AccessControlDAO;
import com.cnnic.whois.execption.ManagementException;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.util.ColumnCache;
import com.cnnic.whois.util.PermissionCache;
import com.cnnic.whois.util.WhoisUtil;

public class AccessControlService {
	private static AccessControlService accessControlService = new AccessControlService();

	private AccessControlService() {
	}

	/**
	 * Get AccessControlService objects
	 * 
	 * @return AccessControlService Object
	 */
	public static AccessControlService getAccessControlService() {
		return accessControlService;
	}

	/**
	 * List permission information
	 * 
	 * @param tableName
	 * @return map collection
	 * @throws ManagementException
	 */
	public Map<String, Object> listPermissionCoulumn(String tableName)
			throws ManagementException {
		AccessControlDAO accessControlDAO = AccessControlDAO
				.getAccessControlDAO();
		return accessControlDAO.listPermissionCoulumn(tableName);
	}

	/**
	 * Update permsission information
	 * 
	 * @param tableName
	 * @param anonymous
	 * @param authenticated
	 * @param root
	 * @throws ManagementException
	 */
	public void updatePermission(String tableName, String[] anonymous,
			String[] authenticated, String[] root) throws ManagementException {
		Map<String, List<String>> permissionList = new HashMap<String, List<String>>();
		for (int i = 0; i < anonymous.length; i++) {
			List<String> userList = new ArrayList<String>();
			String[] anonymousStr = anonymous[i].split(WhoisUtil.PERMISSIONPRX);
			String[] authenticatedStr = authenticated[i]
					.split(WhoisUtil.PERMISSIONPRX);
			String[] rootStr = root[i].split(WhoisUtil.PERMISSIONPRX);

			userList.add(anonymousStr[1]);
			userList.add(authenticatedStr[1]);
			userList.add(rootStr[1]);
			permissionList.put(anonymousStr[0], userList);

		}
		AccessControlDAO accessControlDAO = AccessControlDAO
				.getAccessControlDAO();
		accessControlDAO.updatePermission(tableName, permissionList);
		setPermissionList(tableName);
	}

	/**
	 * When permissions information is updated, the updated information is
	 * stored in the cache to invoke the method
	 * 
	 * @param tableName
	 */
	private void setPermissionList(String tableName) {
		PermissionCache permissionCache = PermissionCache.getPermissionCache();
		
		int typeBinary = Arrays.binarySearch(WhoisUtil.extendColumnTableTypes,
				tableName);//to determine what type of collection
		
		switch (typeBinary) {
		case 0:
			permissionCache.setASMap();
			break;
		case 1:
			permissionCache.setDelegationMap();
			break;
		case 2:
			permissionCache.setDNRDomainMap();
			break;
		case 3:
			permissionCache.setDNREntityMap();
			break;
		case 4:
			permissionCache.setEventsMap();
			break;
		case 5:
			permissionCache.setIPMap();
			break;
		case 6:
			permissionCache.setLinkMap();
			break;
		case 7:
			permissionCache.setNameServerMap();
			break;
		case 8:
			permissionCache.setNoticesMap();
			break;
		case 9:
			permissionCache.setPhonesMap();
			break;
		case 10:
			permissionCache.setPostalAddressMap();
			break;
		case 11:
			permissionCache.setRegistrarMap();
			break;
		case 12:
			permissionCache.setRemarksMap();
			break;
		case 13:
			permissionCache.setRIRDomainMap();
			break;
		case 14:
			permissionCache.setRIREntityMap();
			break;
		case 15:
			permissionCache.setVariantsMap();
			break;
		}
	}

}