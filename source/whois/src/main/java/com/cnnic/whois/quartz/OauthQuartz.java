package com.cnnic.whois.quartz;

import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.quartz.QuartzJobBean;

import com.cnnic.whois.dao.oauth.OAuthAccessorDao;
/**
 * oauth quartz
 * @author nic
 *
 */
public class OauthQuartz extends QuartzJobBean {

	private OAuthAccessorDao oauthAccessorDao;
	
	public OAuthAccessorDao getOauthAccessorDao() {
		return oauthAccessorDao;
	}
	@Autowired
	public void setOauthAccessorDao(OAuthAccessorDao oauthAccessorDao) {
		this.oauthAccessorDao = oauthAccessorDao;
	}
	/**
	 * delete oauth internal
	 */
	@Override
	protected void executeInternal(JobExecutionContext arg0)
			throws JobExecutionException {
		oauthAccessorDao.deleteInvalidDate();
	}
	
}
