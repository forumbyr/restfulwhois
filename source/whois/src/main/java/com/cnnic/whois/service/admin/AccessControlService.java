package com.cnnic.whois.service.admin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.cnnic.whois.dao.admin.AccessControlDAO;
import com.cnnic.whois.execption.ManagementException;
import com.cnnic.whois.util.PermissionCache;
import com.cnnic.whois.util.WhoisUtil;
/**
 * access control service
 * @author nic
 *
 */
@Service
public class AccessControlService {
	
	@Autowired
	private AccessControlDAO accessControlDAO;
	@Autowired
	private PermissionCache permissionCache;

	/**
	 * List permission information
	 * 
	 * @param tableName
	 * @return map collection
	 * @throws ManagementException
	 */
	public Map<String, Object> listPermissionCoulumn(String tableName)
			throws ManagementException {
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
		
		int typeBinary = Arrays.binarySearch(WhoisUtil.extendColumnTableTypes, tableName);//to determine what type of collection
		
		switch (typeBinary) {
		case 0:
			permissionCache.setASMap();
			break;
		case 1:
			permissionCache.setDNRDomainMap();
			break;
		case 2:
			permissionCache.setDNREntityMap();
			break;
		case 3:
			permissionCache.setDsDataMap();
			break;
		case 4:
			permissionCache.setHelpMap();
			break;
		case 5:
			permissionCache.setEventsMap();
			break;
		case 6:
			break;
		case 7:
			permissionCache.setIPMap();
			break;
		case 8:
			permissionCache.setKeyDataMap();
			break;
		case 9:
			permissionCache.setLinkMap();
			break;		
		case 10:
			permissionCache.setNameServerMap();
			break;
		case 11:
			permissionCache.setNoticesMap();
			break;
		case 12:
			permissionCache.setPhonesMap();
			break;
		case 13:
			permissionCache.setPostalAddressMap();
			break;
		case 14:
			permissionCache.setPublicIdsMap();
			break;
		case 15:
			permissionCache.setRegistrarMap();
			break;
		case 16:
			permissionCache.setRemarksMap();
			break;
		case 17:
			permissionCache.setRIRDomainMap();
			break;
		case 18:
			permissionCache.setRIREntityMap();
			break;
		case 19:
			permissionCache.setSecureDNSMap();
			break;
		case 20:
			permissionCache.setVariantsMap();
			break;
		}
	}

}
