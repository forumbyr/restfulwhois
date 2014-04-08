package com.cnnic.whois.controller;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.cnnic.whois.bean.DomainQueryParam;
import com.cnnic.whois.bean.EntityQueryParam;
import com.cnnic.whois.bean.IpQueryParam;
import com.cnnic.whois.bean.NsQueryParam;
import com.cnnic.whois.bean.PageBean;
import com.cnnic.whois.bean.QueryParam;
import com.cnnic.whois.bean.QueryType;
import com.cnnic.whois.dao.query.search.AbstractSearchQueryDao;
import com.cnnic.whois.dao.query.search.EntityQueryDao;
import com.cnnic.whois.execption.QueryException;
import com.cnnic.whois.service.QueryService;
import com.cnnic.whois.util.WhoisUtil;
import com.cnnic.whois.util.validate.ValidateUtils;
import com.cnnic.whois.view.FormatType;
import com.cnnic.whois.view.ViewResolver;

/**
 * base controller
 * 
 * @author nic
 * 
 */
public class BaseController {
	@Autowired
	protected ViewResolver viewResolver;

	private static Logger logger = LoggerFactory
			.getLogger(BaseController.class);

	/**
	 * set max records for fuzzy query param
	 * 
	 * @param queryParam
	 *            :query params
	 */
	protected void setMaxRecordsForFuzzyQ(QueryParam queryParam) {
		if (queryParam.getFormat().isJsonOrXmlFormat()) {
			queryParam.getPage().setMaxRecords(
					QueryService.MAX_SIZE_FUZZY_QUERY);
		}
	}

	/**
	 * construct domain param
	 * 
	 * @param request
	 *            :http request
	 * @return: domain param
	 */
	protected DomainQueryParam praseDomainQueryParams(HttpServletRequest request) {
		request.setAttribute("queryType", "domain");
		FormatType formatType = getFormatType(request);
		logger.info("formatType:" + formatType);
		PageBean page = getPageParam(request);
		return new DomainQueryParam(formatType, page);
	}

	/**
	 * construct ns param from request
	 * 
	 * @param request
	 *            :http request
	 * @return: domain param
	 */
	protected NsQueryParam parseNsQueryParams(HttpServletRequest request) {
		FormatType formatType = getFormatType(request);
		logger.info("formatType:" + formatType);
		PageBean page = getPageParam(request);
		return new NsQueryParam(formatType, page);
	}

	/**
	 * construct entity param
	 * 
	 * @param request
	 *            :http request
	 * @return entity param
	 */
	protected EntityQueryParam praseEntityQueryParams(HttpServletRequest request) {
		FormatType formatType = getFormatType(request);
		PageBean page = getPageParam(request);
		return new EntityQueryParam(formatType, page);
	}

	/**
	 * construct param
	 * 
	 * @param request
	 *            :http request
	 * @return param
	 */
	public static QueryParam praseQueryParams(HttpServletRequest request) {
		FormatType formatType = getFormatType(request);
		PageBean page = getPageParam(request);
		return new QueryParam(formatType, page);
	}

	/**
	 * construct ip query param
	 * 
	 * @param request
	 *            :http request
	 * @return ip query param
	 */
	protected IpQueryParam praseIpQueryParams(HttpServletRequest request) {
		FormatType formatType = getFormatType(request);
		PageBean page = getPageParam(request);
		return new IpQueryParam(formatType, page);
	}

	/**
	 * get page param
	 * 
	 * @param request
	 * @return page param
	 */
	private static PageBean getPageParam(HttpServletRequest request) {
		Object currentPageObj = request.getParameter("currentPage");
		PageBean page = new PageBean();
		if (null != currentPageObj) {
			page.setCurrentPage(Integer.valueOf(currentPageObj.toString()));
		}
		return page;
	}

	/**
	 * render response
	 * 
	 * @param request
	 *            :http request
	 * @param response
	 *            :http reponse
	 * @param resultMap
	 *            :query result map
	 * @param queryParam
	 *            :query param
	 * @throws IOException
	 * @throws ServletException
	 */
	protected void renderResponse(HttpServletRequest request,
			HttpServletResponse response, Map<String, Object> resultMap,
			QueryParam queryParam) throws IOException, ServletException {
		viewResolver.writeResponse(queryParam.getFormat(),
				queryParam.getQueryType(), request, response, resultMap);
	}

	/**
	 * render response error 400
	 * 
	 * @param request
	 *            :http request
	 * @param response
	 *            :http response
	 * @param queryParam
	 *            :query param
	 * @throws IOException
	 * @throws ServletException
	 * @throws QueryException
	 */
	protected void renderResponseError400(HttpServletRequest request,
			HttpServletResponse response, QueryParam queryParam)
			throws IOException, ServletException, QueryException {
		Map<String, Object> resultMap = WhoisUtil.processError(
				WhoisUtil.COMMENDRRORCODE, queryParam);
		viewResolver.writeResponse(getFormatType(request),
				getQueryType(request), request, response, resultMap);
	}

	/**
	 * render response for error 422
	 * 
	 * @param request
	 *            :http request
	 * @param response
	 *            :http response
	 * @param queryParam
	 *            :query param
	 * @throws IOException
	 * @throws ServletException
	 * @throws QueryException
	 */
	protected void renderResponseError422(HttpServletRequest request,
			HttpServletResponse response, QueryParam queryParam)
			throws IOException, ServletException, QueryException {
		Map<String, Object> resultMap = WhoisUtil.processError(
				WhoisUtil.UNPROCESSABLEERRORCODE, queryParam);
		viewResolver.writeResponse(getFormatType(request),
				getQueryType(request), request, response, resultMap);
	}

	/**
	 * get format from cooike
	 * 
	 * @param request
	 *            :http request
	 * @return format
	 */
	public static String getFormatCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		String format = null;
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("Format")) {
					return cookie.getValue();
				}
			}
		}
		return format;
	}

	/**
	 * get format type
	 * 
	 * @param request
	 *            :http request
	 * @return format type
	 */
	public static FormatType getFormatType(HttpServletRequest request) {
		String format = getFormatCookie(request);
		if (StringUtils.isNotBlank(format)) {
			return FormatType.getFormatType(format);
		}
		if (isWebBrowser(request)) {
			return FormatType.HTML;
		}
		String acceptHeader = request.getHeader("Accept");
		if (StringUtils.isNotBlank(acceptHeader)
				&& acceptHeader.contains("text")) {
			format = FormatType.TEXTPLAIN.getName();
		} else if (StringUtils.isNotBlank(acceptHeader)
				&& acceptHeader.contains("html")) {
			format = FormatType.HTML.getName();
		} else {
			format = FormatType.JSON.getName();
		}
		return FormatType.getFormatType(format);
	}

	/**
	 * get query type
	 * 
	 * @param request
	 *            :http request
	 * @return query type
	 */
	public static QueryType getQueryType(HttpServletRequest request) {
		if (request.getAttribute("queryType") != null) {
			String queryType = (String) request.getAttribute("queryType");
			return QueryType.getQueryType(queryType);
		} else {
			QueryParam param = (QueryParam) request.getAttribute("queryPara");// TODO:delete
			return param.getQueryType();
		}
	}

	/**
	 * is web browser
	 * 
	 * @param request
	 *            :http request
	 * @return true if is,false if not
	 */
	public static boolean isWebBrowser(HttpServletRequest request) {
		String userAgent = "";
		try {
			userAgent = request.getHeader("user-agent").toLowerCase();
		} catch (Exception e) {
			userAgent = "";
		}
		if (userAgent.contains("msie") || userAgent.contains("firefox")
				|| userAgent.contains("chrome") || userAgent.contains("safiri")
				|| userAgent.contains("opera")) {
			return true;
		}
		return false;
	}

	/**
	 * get normalization format string
	 * 
	 * @param str
	 *            :string
	 * @return formated string
	 */
	protected String getNormalization(String str) {
		if (StringUtils.isBlank(str)) {
			return str;
		}
		return Normalizer.normalize(str, Form.NFKC);
	}

	/**
	 * generate ns query params by ip,use solr
	 * 
	 * @param queryParam
	 *            :origin queryParam
	 * @param ip
	 *            :ip param
	 * @param request
	 *            :http request
	 */
	protected void geneNsFuzzyQByIp(QueryParam queryParam, String ip,
			HttpServletRequest request) {
		request.setAttribute("queryPara", ip);
		queryParam.setQueryType(QueryType.SEARCHNS);
		String solrQ = ip.replace("\\:", ":");
		if (ValidateUtils.isIpv4(solrQ)) {
			solrQ = EntityQueryDao.geneNsQByPreciseIpv4(solrQ);
		} else if (ValidateUtils.isIPv6(solrQ)) {
			solrQ = EntityQueryDao.geneNsQByPreciseIpv6(solrQ);
		}
		queryParam.setQ(solrQ);
		request.setAttribute("pageBean", queryParam.getPage());
		request.setAttribute("queryPath", "nameservers");
		setMaxRecordsForFuzzyQ(queryParam);
	}

	/**
	 * generate ns fuzzy query by ns name,use solr
	 * 
	 * @param queryParam
	 * @param domainQ
	 * @param punyQ
	 * @param request
	 */
	protected void geneNsFuzzyQByName(QueryParam queryParam, String domainQ,
			String punyQ, HttpServletRequest request) {
		queryParam.setQueryType(QueryType.SEARCHNS);
		request.setAttribute("pageBean", queryParam.getPage());
		request.setAttribute("queryPath", "nameservers");

		String escapeQ = AbstractSearchQueryDao.escapeSolrChar(domainQ);
		String escapePunyQ = AbstractSearchQueryDao.escapeSolrChar(punyQ);
		String queryStr = "unicodeName:" + escapeQ;
		if (domainQ.startsWith("xn--") || domainQ.contains(".xn--")) {
			queryStr = "ldhName:" + escapePunyQ + " OR " + queryStr;
		}
		queryParam.setQ(queryStr);
		setMaxRecordsForFuzzyQ(queryParam);
	}
	
	/**
	 * decode and trim str
	 * @param str 
	 * @return str after decode and gtrim
	 * @throws UnsupportedEncodingException
	 */
	protected String decodeAndTrim(String str) throws UnsupportedEncodingException{
		if (StringUtils.isBlank(str)) {
			return StringUtils.trim(str);
		}
		str = WhoisUtil.urlDecode(str);
		str = StringUtils.trim(str);
		return str ;
	}
}