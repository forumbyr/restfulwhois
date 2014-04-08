/*
 * Copyright 2007 AOL, LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.cnnic.whois.controller.oauth;

import java.io.IOException;
import java.net.IDN;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cnnic.whois.bean.Authentication;
import com.cnnic.whois.bean.EntityQueryParam;
import com.cnnic.whois.bean.IpQueryParam;
import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.oauth.OAuthAccessorBean;
import com.cnnic.whois.controller.BaseController;
import com.cnnic.whois.dao.oauth.OAuthAccessorDao;
import com.cnnic.whois.dao.oauth.OAuthProvider;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.execption.RedirectExecption;
import com.cnnic.whois.service.QueryService;
import com.cnnic.whois.util.AuthenticationHolder;
import com.cnnic.whois.util.WhoisUtil;
import com.cnnic.whois.util.validate.ValidateUtils;
import com.cnnic.whois.view.ViewResolver;

import net.oauth.OAuthAccessor;
import net.oauth.OAuthMessage;
import net.oauth.server.OAuthServlet;

/**
 * A text servlet to echo incoming "echo" param along with userId
 */
@Controller
public class EchoController extends BaseController {

	@Autowired
	private QueryService queryService;
	@Autowired
	private ViewResolver viewResolver;
	@Autowired
	private OAuthAccessorDao oauthAccessorDao;
	@Autowired
	private OAuthProvider oauthProvider;
	/**
	 * query domain
	 * @param request
	 * @param response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/echo")
	@ResponseBody
	public void queryDomain(HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		try {
			OAuthMessage requestMessage = OAuthServlet
					.getMessage(request, null);
			OAuthAccessor accessor = oauthProvider.getAccessor(requestMessage);
			OAuthProvider.VALIDATOR.validateMessage(requestMessage, accessor);
			accessApi(accessor.accessToken, request, response);
		} catch (Exception e) {
			OAuthProvider.handleException(e, request, response, false);
		}
	}
	/**
	 * access query api
	 * @param accessToken
	 * @param request
	 * @param response
	 * @throws Exception
	 */
	private void accessApi(String accessToken, HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		OAuthAccessorBean oauthAccessorBean = oauthAccessorDao.getOAuthAccessorBeanByAccessToken(accessToken);
		AuthenticationHolder.setAuthentication(new Authentication(oauthAccessorBean.getOauth_user_role()));
		
		 for (Object item : request.getParameterMap().entrySet()) {
                Map.Entry parameter = (Map.Entry) item;
                String[] values = (String[]) parameter.getValue();
                for (String value : values) {
                	
                	if(value.equals("ip")){
                		
                		String net = "0";
                		String ip = StringUtils.trim("1.1.1.1");
                		
                		Map<String, Object> resultMap = null;
                		IpQueryParam queryParam = super.praseIpQueryParams(request);
                		String strInfo = ip;
                		if (!ValidateUtils.verifyIP(strInfo, net)) {
                			resultMap = WhoisUtil.processError(WhoisUtil.COMMENDRRORCODE,queryParam);
                			viewResolver.writeResponse(queryParam.getFormat(), queryParam.getQueryType(),
                					request, response, resultMap);
                			return;
                		}
                		queryParam.setQ(ip);
                		queryParam.setIpInfo(strInfo);
                		queryParam.setIpLength(Integer.parseInt(net));
                		resultMap = queryService.queryIP(queryParam);
                		request.setAttribute("queryPara", ip);
                		request.setAttribute("queryType", "ip");
                		viewResolver.writeResponse(queryParam.getFormat(), queryParam.getQueryType(),
            					request, response, resultMap);
                	}
                	if(value.equals("domain")){
                		String domainName = StringUtils.trim("z.cn");
            			String queryParaPuny = IDN.toASCII(domainName);
            			Map<String, Object> resultMap = null;
            			QueryParam queryParam = super.praseQueryParams(request);
            			if (!ValidateUtils.validateDomainNameIsValidIdna(queryParaPuny)) {
            				resultMap = WhoisUtil.processError(WhoisUtil.COMMENDRRORCODE,queryParam);
            			} else {
            				queryParam.setQ(domainName);
            				resultMap = queryService.queryDomain(queryParam);
            				System.err.println(resultMap);
            			}
            			viewResolver.writeResponse(queryParam.getFormat(), queryParam.getQueryType(),
            					request, response, resultMap);
                	}
                	if(value.equals("entity")){
                		EntityQueryParam queryParam = super.praseEntityQueryParams(request);
                		queryParam.setQ("IBM-1");
                		Map<String, Object> resultMap = queryService.queryEntity(queryParam);
                		request.setAttribute("queryType", "entity");
                		request.setAttribute("queryPara", "IBM-1");
                		renderResponse(request, response, resultMap, queryParam);
                	}
                }
            }
	}

}
