package com.cnnic.whois.service.admin;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.cnnic.whois.dao.admin.RedirectionDAO;
import com.cnnic.whois.execption.ManagementException;
import com.cnnic.whois.util.IpUtil;
import com.cnnic.whois.util.TransformUtils;
import com.cnnic.whois.util.WhoisUtil;
/**
 * redirect service
 * @author nic
 *
 */
@Service
public class RedirectionService {
	
	@Autowired
	private RedirectionDAO redirectionDao;

	/**
	 * Add redirection information
	 * @param startNumber
	 * @param endNumber
	 * @param redirectUrl
	 * @param tableName
	 * @throws ManagementException
	 */
	public void addRedirect(String startNumber, String endNumber,
			String redirectUrl, String tableName) throws ManagementException {
		if (tableName.endsWith(WhoisUtil.IP)) {
			String[] startAddress = TransformUtils.isIPMaskNetWork(startNumber);
			String[] endAddress = TransformUtils.isIPMaskNetWork(endNumber);
			
			long[] ipLongs = IpUtil.parsingIp(startAddress[0],
					endAddress[0], Integer.parseInt(startAddress[1]),
					Integer.parseInt(endAddress[1]));

			redirectionDao.addIPRedirection(ipLongs[0], ipLongs[1], ipLongs[2],
					ipLongs[3], redirectUrl);
			return;
		} else if (tableName.endsWith(WhoisUtil.AUTNUM)) {
			redirectionDao.addAutnumRedirection(startNumber, endNumber, redirectUrl);
			return;
		}
		redirectionDao.addDomainRedirection(startNumber, redirectUrl);
	}

	private String[] isIPMaskNetWork(String ipInfo) {
		String[] infoArray = new String[2];
		if (ipInfo.indexOf(WhoisUtil.PRX) >= 0) {
			infoArray = ipInfo.split(WhoisUtil.PRX);
		} else {
			infoArray[0] = ipInfo;
			infoArray[1] = "0";
		}
		return infoArray;
	}

	/**
	 * List redirection information
	 * 
	 * @param tableName
	 * @return map collection
	 * @throws ManagementException
	 */
	public Map<Integer, List<String>> listRedirect(String tableName)
			throws ManagementException {
		return redirectionDao.listRedirect(tableName);
	}

	/**
	 * Update redirection information
	 * @param startNumber
	 * @param endNumber
	 * @param redirectUrl
	 * @param id
	 * @param tableName
	 * @throws ManagementException
	 */
	public void updateRedirect(String startNumber, String endNumber,
			String redirectUrl, int id, String tableName)
			throws ManagementException {
		
		if (tableName.endsWith(WhoisUtil.IP)) {
			String[] startAddress = isIPMaskNetWork(startNumber);
			String[] endAddress = isIPMaskNetWork(endNumber);

			long[] ipLongs = IpUtil.parsingIp(startAddress[0],
					endAddress[0], Integer.parseInt(startAddress[1]),
					Integer.parseInt(endAddress[1]));;
			
			redirectionDao.updateIPRedirection(ipLongs[0], ipLongs[1], ipLongs[2],
					ipLongs[3], id,redirectUrl);
			return;
		} else if (tableName.endsWith(WhoisUtil.AUTNUM)) {
			redirectionDao.updateAutnumRedirection(startNumber, endNumber,id,
					redirectUrl);
			return;
		}
		redirectionDao.updateDomainRedirection(startNumber,id, redirectUrl);
	}

	/**
	 * Delete redirection information
	 * 
	 * @param id
	 * @param tableName
	 * @throws ManagementException
	 */
	public void deleteRedirect(int id, String tableName)
			throws ManagementException {
		redirectionDao.deleteRedirect(id, tableName);
	}

}