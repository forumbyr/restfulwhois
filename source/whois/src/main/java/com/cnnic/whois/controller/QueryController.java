package com.cnnic.whois.controller;

import java.io.IOException;
import java.net.IDN;
import java.sql.SQLException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.cnnic.whois.bean.DomainQueryParam;
import com.cnnic.whois.bean.EntityQueryParam;
import com.cnnic.whois.bean.IpQueryParam;
import com.cnnic.whois.bean.NsQueryParam;
import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.execption.RedirectExecption;
import com.cnnic.whois.service.QueryService;
import com.cnnic.whois.util.WhoisUtil;
import com.cnnic.whois.util.validate.ValidateUtils;
/**
 * query controller,mapping url begin with ".well-known/rdap/"
 * 
 * @author nic
 *
 */
@Controller
@RequestMapping("/{dot}well-known/rdap")
public class QueryController extends BaseController {
	@Autowired
	private QueryService queryService;
	
	/**
	 * api doc
	 * @return
	 */
	@RequestMapping(value = { "/", "" }, method = RequestMethod.GET)
	public String index() {
		return "/doc/index";
	}
	/**
	 * fuzzy query domain by domain name
	 * @param name : domain name
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/domains", method = RequestMethod.GET)
	@ResponseBody
	public void fuzzyQueryDomain(@RequestParam(required = false) String name,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, RedirectExecption, IOException,
			ServletException {
		DomainQueryParam domainQueryParam = super.praseDomainQueryParams(request);
		if (StringUtils.isBlank(name)) {
			super.renderResponseError400(request, response,domainQueryParam);
			return;
		}
		try {
			name = super.decodeAndTrim(name);
		} catch (Exception e) {
			super.renderResponseError400(request, response,domainQueryParam);
			return;
		}
		name = super.getNormalization(name);
		Map<String, Object> resultMap = null;
		if (ValidateUtils.ASTERISK.equals(name)|| name.startsWith(ValidateUtils.ASTERISK)) {
			super.renderResponseError422(request, response,domainQueryParam);
			return;
		}
		String punyDomainName = name;
		try {
			punyDomainName = IDN.toASCII(name);// long lable exception/not utf8 exception
		} catch (Exception e) {
			super.renderResponseError400(request, response,domainQueryParam);
			return;
		}
		request.setAttribute("queryPara", IDN.toUnicode(punyDomainName));
		if (!ValidateUtils.validateFuzzyDomain(name)) {
			super.renderResponseError400(request, response,domainQueryParam);
			return;
		}
		name = ValidateUtils.deleteLastPoint(name);
		name = WhoisUtil.getLowerCaseByLabel(name);
		domainQueryParam.setQueryType(QueryType.SEARCHDOMAIN);
		domainQueryParam.setQ(name);
		domainQueryParam.setDomainPuny(punyDomainName);
		setMaxRecordsForFuzzyQ(domainQueryParam);
		domainQueryParam.setFuzzyQ(true);
		resultMap = queryService.query(domainQueryParam);
		request.setAttribute("pageBean", domainQueryParam.getPage());
		request.setAttribute("queryPath", "domains");
		renderResponse(request, response, resultMap, domainQueryParam);
	}
	
	/**
	 * precise query domain by domain name
	 * @param domainName:domain name
	 * @param request:http request
	 * @param response:http response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = {"/domain/{domainName}"}, method = RequestMethod.GET)
	@ResponseBody
	public void queryDomain(@PathVariable String domainName,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, RedirectExecption, IOException,
			ServletException {
		DomainQueryParam domainQueryParam = super.praseDomainQueryParams(request);
		if (StringUtils.isBlank(domainName)) {
			super.renderResponseError400(request, response,domainQueryParam);
			return;
		}
		try {
			domainName = super.decodeAndTrim(domainName);
		} catch (Exception e) {
			super.renderResponseError400(request, response,domainQueryParam);
			return;
		}
		String punyDomainName = domainName;
		Map<String, Object> resultMap = null;
		try {
			punyDomainName = IDN.toASCII(domainName);// long lable exception
		} catch (Exception e) {
			super.renderResponseError400(request, response,domainQueryParam);
			return;
		}
		request.setAttribute("queryPara", IDN.toUnicode(punyDomainName));
		if (!ValidateUtils.validateDomainNameIsValidIdna(domainName)) {
			resultMap = WhoisUtil.processError(WhoisUtil.COMMENDRRORCODE,domainQueryParam);
		} else {
			domainName = ValidateUtils.deleteLastPoint(domainName);
			domainName = WhoisUtil.getLowerCaseByLabel(domainName);
			domainQueryParam.setQueryType(QueryType.DOMAIN);
			domainQueryParam.setQ(domainName);
			domainQueryParam.setDomainPuny(punyDomainName);
			resultMap = queryService.queryDomain(domainQueryParam);
		}
		renderResponse(request, response, resultMap, domainQueryParam);
	}

	/**
	 * fuzzy query entity by name or handle
	 * @param fn:entity name param
	 * @param handle:entity handle param
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws SQLException
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/entities", method = RequestMethod.GET)
	@ResponseBody
	public void fuzzyQueryEntity(@RequestParam(required = false) String fn,
			@RequestParam(required = false) String handle,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, SQLException, IOException, ServletException {
		Map<String, Object> resultMap = null;
		EntityQueryParam queryParam = super.praseEntityQueryParams(request);
		request.setAttribute("queryType", "entity");
		if (StringUtils.isBlank(fn) && StringUtils.isBlank(handle)) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		String q = handle;
		if (StringUtils.isNotBlank(fn)) {
			q = fn;
		}
		if(q.length()>ValidateUtils.MAX_DOMAIN_LENGTH_WITHOUT_LAST_DOT){
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		try {
			q = super.decodeAndTrim(q);
		} catch (Exception e) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		q = super.getNormalization(q);
		if (ValidateUtils.ASTERISK.equals(q) || q.startsWith(ValidateUtils.ASTERISK)) {
			super.renderResponseError422(request, response,queryParam);
			return;
		}
		String fuzzyQuerySolrPropName = "handle";
		String paramName = "handle";
		if (StringUtils.isNotBlank(fn)) {
			fuzzyQuerySolrPropName = "entityNames";
			paramName = "fn";
		}
		queryParam.setQueryType(QueryType.SEARCHENTITY);
		queryParam.setFuzzyQueryParamName(fuzzyQuerySolrPropName);
		queryParam.setQ(q);
		setMaxRecordsForFuzzyQ(queryParam);
		resultMap = queryService.fuzzyQueryEntity(queryParam);
		request.setAttribute("pageBean", queryParam.getPage());
		request.setAttribute("queryPath", "entities");
		request.setAttribute("queryPara", paramName + ":" + q);
		renderResponse(request, response, resultMap, queryParam);
	}

	/**
	 * precise query entity by name
	 * @param entityName:entity name
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws SQLException
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/entity/{handle}", method = RequestMethod.GET)
	@ResponseBody
	public void queryEntity(@PathVariable String handle,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, SQLException, IOException, ServletException {
		EntityQueryParam queryParam = super.praseEntityQueryParams(request);
		queryParam.setQueryType(QueryType.ENTITY);
		request.setAttribute("queryType", "entity");
		request.setAttribute("queryPara", handle);
		if (StringUtils.isBlank(handle) || handle.length()>ValidateUtils.MAX_DOMAIN_LENGTH_WITHOUT_LAST_DOT) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		try {
			handle = super.decodeAndTrim(handle);
		} catch (Exception e) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		queryParam.setQ(handle);
		Map<String, Object> resultMap = queryService.queryEntity(queryParam);
		renderResponse(request, response, resultMap, queryParam);
	}

	/**
	 * fuzzy query ns by ns name, or ip 
	 * @param name:ns name
	 * @param ip:ns's ip.if 'name' param is not blank, 'ip' param will be ignored
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws SQLException
	 * @throws IOException
	 * @throws ServletException
	 * @throws RedirectExecption
	 */
	@RequestMapping(value = "/nameservers", method = RequestMethod.GET)
	@ResponseBody
	public void fuzzyQueryNs(@RequestParam(required = false) String name, 
			@RequestParam(required = false) String ip,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, SQLException, IOException, ServletException,
			RedirectExecption {
		Map<String, Object> resultMap = null;
		NsQueryParam queryParam = super.parseNsQueryParams(request);
		request.setAttribute("queryType", "nameserver");
		queryParam.setFuzzyQ(true);
		if (StringUtils.isBlank(name) && StringUtils.isBlank(ip)) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		if(StringUtils.isNotBlank(name)){
			if(name.length()>ValidateUtils.MAX_DOMAIN_LENGTH_WITHOUT_LAST_DOT){
				super.renderResponseError400(request, response,queryParam);
				return;
			}
			try {
				name = super.decodeAndTrim(name);
			} catch (Exception e) {
				super.renderResponseError400(request, response,queryParam);
				return;
			}
			name = super.getNormalization(name);
			if (ValidateUtils.ASTERISK.equals(name) || name.startsWith(ValidateUtils.ASTERISK)) {
				super.renderResponseError422(request, response,queryParam);
				return;
			}
			String punyName = name;
			try {
				// long lable exception/not utf8 exception
				punyName = IDN.toASCII(name);
			} catch (Exception e) {
				super.renderResponseError400(request, response,queryParam);
				return;
			}
			request.setAttribute("queryPara", name);
			if (!ValidateUtils.validateFuzzyDomain(name)) {
				super.renderResponseError400(request, response,queryParam);
				return;
			} else {
				name = ValidateUtils.deleteLastPoint(name);
				name = WhoisUtil.getLowerCaseByLabel(name);
				geneNsFuzzyQByName(queryParam, name,punyName, request);
				resultMap = queryService.fuzzyQueryNameServer(queryParam);
				renderResponse(request, response, resultMap, queryParam);
				return;
			}
		}else if(StringUtils.isNotBlank(ip)){
			if(ip.length()>ValidateUtils.MAX_DOMAIN_LENGTH_WITHOUT_LAST_DOT){
				super.renderResponseError400(request, response,queryParam);
				return;
			}
			if (!ValidateUtils.verifyIP(ip)) {
				super.renderResponseError400(request, response,queryParam);
				return;
			}
			geneNsFuzzyQByIp(queryParam, ip, request);
			resultMap = queryService.fuzzyQueryNameServer(queryParam);
			renderResponse(request, response, resultMap, queryParam);
		}
	}
	
	/**
	 * precise query ns by ns name
	 * @param nsName:ns name
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws SQLException
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/nameserver/{nsName}", method = RequestMethod.GET)
	@ResponseBody
	public void queryNs(@PathVariable String nsName,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, SQLException, IOException, ServletException {
		request.setAttribute("queryType", "nameserver");
		NsQueryParam queryParam = super.parseNsQueryParams(request);
		if (StringUtils.isBlank(nsName)) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		String punyNsName = nsName;
		try{
			try {
				nsName = super.decodeAndTrim(nsName);
			} catch (Exception e) {
				super.renderResponseError400(request, response,queryParam);
				return;
			}
			punyNsName = IDN.toASCII(nsName);
			// long lable exception/not utf8 exception
		} catch (Exception e) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		Map<String, Object> resultMap = null;
		if (!ValidateUtils.validateDomainNameIsValidIdna(nsName)) {
			resultMap = WhoisUtil.processError(WhoisUtil.COMMENDRRORCODE,queryParam);
		} else {
			nsName = ValidateUtils.deleteLastPoint(nsName);
			nsName = WhoisUtil.getLowerCaseByLabel(nsName);
			queryParam.setQ(nsName);
			queryParam.setDomainPuny(punyNsName);
			queryParam.setQueryType(QueryType.NAMESERVER);
			resultMap = queryService.query(queryParam);
			request.setAttribute("queryPara", IDN.toUnicode(punyNsName));
		}
		renderResponse(request, response, resultMap, queryParam);
	}

	/**
	 * query Autonomous number
	 * @param autnum : as number
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/autnum/{autnum}", method = RequestMethod.GET)
	@ResponseBody
	public void queryAs(@PathVariable String autnum,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, RedirectExecption, IOException,
			ServletException {
		QueryParam queryParam = super.praseQueryParams(request);
		if(StringUtils.isBlank(autnum) || autnum.length()>ValidateUtils.MAX_DOMAIN_LENGTH_WITHOUT_LAST_DOT){
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		queryParam.setQ(autnum);
		Map<String, Object> resultMap = queryService.queryAS(queryParam);
		request.setAttribute("queryType", "autnum");
		request.setAttribute("queryPara", autnum);
		renderResponse(request, response, resultMap, queryParam);
	}

	@RequestMapping(value = "/dsData/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void queryDsData(@PathVariable String q, HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		query(QueryType.DSDATA, q, request, response);
	}

	/**
	 * query event by handle
	 * @param q:envent handle
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/events/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void queryEvents(@PathVariable String q, HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		query(QueryType.EVENTS, q, request, response);
	}

	/**
	 * query help
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/help", method = RequestMethod.GET)
	@ResponseBody
	public void queryHelp(HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		Map<String, Object> resultMap = null;
		QueryParam queryParam = super.praseQueryParams(request);
		queryParam.setQ("helpID");
		resultMap = queryService.queryHelp(queryParam);
		renderResponse(request, response, resultMap, queryParam);
	}

	/**
	 * query ip error with tail '/',return 400 error
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = { "/ip/{ip}/" }, method = RequestMethod.GET)
	@ResponseBody
	public void queryIpErrTail(HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		QueryParam queryParam = super.praseQueryParams(request);
		request.setAttribute("queryType", "ip");
		super.renderResponseError400(request, response,queryParam);
		return;
	}
	
	/**
	 * query ip by ip address,return subnet info of the ip
	 * @param ip:ip v4/v6 address
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = { "/ip/{ip}" }, method = RequestMethod.GET)
	@ResponseBody
	public void queryIp(@PathVariable String ip, HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		String net = "0";
		doQueryIp(ip, request, response, net);
	}

	/**
	 * query ip with net mask
	 * @param ip:ip v4/v6 address
	 * @param net:net mask.should between [0-32] when ipv4, and between [0-128] when ipv6,Contains the boundary
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = { "/ip/{ip}/{net}", "/ip/{ip}/{net}/" }, method = RequestMethod.GET)
	@ResponseBody
	public void queryIpWithNet(@PathVariable String ip,
			@PathVariable String net, HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		net = StringUtils.trim(net);
		doQueryIp(ip, request, response, net);
	}

	private void doQueryIp(String ip, HttpServletRequest request,
			HttpServletResponse response, String ipLength)
			throws QueryException, IOException, ServletException,
			RedirectExecption {
		ip = StringUtils.trim(ip);
		Map<String, Object> resultMap = null;
		IpQueryParam queryParam = super.praseIpQueryParams(request);
		if(StringUtils.isBlank(ip)){
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		String strInfo = ip;
		request.setAttribute("queryPara", ip);
		request.setAttribute("queryType", "ip");
		String uri = request.getRequestURI();
		if(uri.indexOf("//") != -1){
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		if (!ValidateUtils.verifyIP(strInfo, ipLength)) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		queryParam.setQ(ip);
		queryParam.setIpInfo(strInfo);
		queryParam.setIpLength(Integer.parseInt(ipLength));
		resultMap = queryService.queryIP(queryParam);
		viewResolver.writeResponse(queryParam.getFormat(),
				queryParam.getQueryType(), request, response, resultMap);
	}

	@RequestMapping(value = "/keyData/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void queryKeyData(@PathVariable String q,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, RedirectExecption, IOException,
			ServletException {
		query(QueryType.KEYDATA, q, request, response);
	}

	/**
	 * query link by link id
	 * @param q:link id
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/links/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void queryLinks(@PathVariable String q, HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		query(QueryType.LINKS, q, request, response);
	}

	/**
	 * query notice by notice id
	 * @param q:notice id
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/notices/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void queryNotices(@PathVariable String q,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, RedirectExecption, IOException,
			ServletException {
		query(QueryType.NOTICES, q, request, response);
	}

	/**
	 * query phone by phone id
	 * @param q:phone id
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/phones/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void queryPhones(@PathVariable String q, HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		query(QueryType.PHONES, q, request, response);
	}

	/**
	 * query address by address id
	 * @param q:address id
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/postalAddress/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void queryPostalAddress(@PathVariable String q,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, RedirectExecption, IOException,
			ServletException {
		query(QueryType.POSTALADDRESS, q, request, response);
	}

	/**
	 * query securedns by id
	 * @param q:securedns id
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/secureDNS/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void querySecureDNS(@PathVariable String q,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, RedirectExecption, IOException,
			ServletException {
		query(QueryType.SECUREDNS, q, request, response);
	}

	/**
	 * query remark by id
	 * @param q: remark id
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/remarks/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void queryRemarks(@PathVariable String q,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, RedirectExecption, IOException,
			ServletException {
		query(QueryType.REMARKS, q, request, response);
	}

	/**
	 * query variant by id
	 * @param q:variant id
	 * @param request:http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws RedirectExecption
	 * @throws IOException
	 * @throws ServletException
	 */
	@RequestMapping(value = "/variants/{q}", method = RequestMethod.GET)
	@ResponseBody
	public void queryVariants(@PathVariable String q,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, RedirectExecption, IOException,
			ServletException {
		query(QueryType.VARIANTS, q, request, response);
	}

	/**
	 * common query
	 * @param queryType:query type @see QueryType
	 * @param q:query param
	 * @param request :http request
	 * @param response:http response
	 * @throws QueryException
	 * @throws IOException
	 * @throws ServletException
	 */
	private void query(QueryType queryType, String q,
			HttpServletRequest request, HttpServletResponse response)
			throws QueryException, IOException, ServletException {
		Map<String, Object> resultMap = null;
		QueryParam queryParam = praseQueryParams(request);
		queryParam.setQueryType(queryType);
		if (StringUtils.isBlank(q)) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		try {
			q = super.decodeAndTrim(q);
		} catch (Exception e) {
			super.renderResponseError400(request, response,queryParam);
			return;
		}
		queryParam.setQ(q);
		request.setAttribute("queryType", queryType.getName());
		resultMap = queryService.query(queryParam);
		request.setAttribute("queryPara", q);
		renderResponse(request, response, resultMap, queryParam);
	}

	/**
	 * other invalid query uri will response 400 error
	 */
	@RequestMapping(value = "/**")
	@ResponseBody
	public void error400(HttpServletRequest request,
			HttpServletResponse response) throws QueryException,
			RedirectExecption, IOException, ServletException {
		QueryParam queryParam = praseQueryParams(request);
		Map<String, Object> resultMap = WhoisUtil
				.processError(WhoisUtil.COMMENDRRORCODE,queryParam);
		renderResponse(request, response, resultMap, queryParam);
		return;
	}

	/**
	 * redirect exception handle,response 301
	 * @param ex:exception
	 * @param request:http request
	 * @param response:http response
	 * @return null
	 */
	@ExceptionHandler(value = { RedirectExecption.class })
	@ResponseStatus(value = HttpStatus.MOVED_PERMANENTLY)
	public String exp(Exception ex, HttpServletRequest request,
			HttpServletResponse response) {
		RedirectExecption rEx = (RedirectExecption) ex;
		response.setHeader("Accept", getFormatCookie(request));
		response.setHeader("Location", rEx.getRedirectURL());
		response.setHeader("Connection", "close");
		return null;
	}
}
