package com.cnnic.whois.service;

import java.net.MalformedURLException;
import java.util.List;

import org.apache.solr.client.solrj.SolrQuery;
import org.apache.solr.client.solrj.SolrServerException;
import org.apache.solr.client.solrj.beans.DocumentObjectBinder;
import org.apache.solr.client.solrj.impl.CommonsHttpSolrServer;
import org.apache.solr.client.solrj.response.QueryResponse;
import org.apache.solr.common.SolrInputDocument;

import com.cnnic.whois.bean.Domain;
import com.cnnic.whois.bean.index.DomainIndex;
import com.cnnic.whois.bean.index.SearchCondition;
import com.cnnic.whois.service.index.SearchResult;
import com.cnnic.whois.util.WhoisProperties;

public class DomainIndexService {
	private static DomainIndexService indexService = new DomainIndexService(
			WhoisProperties.getDomainSolrUrl());
	private CommonsHttpSolrServer server;
	
	public static DomainIndexService getIndexService() {
		return indexService;
	}

	public static void main(String[] args) {
		// DnrDomain dnrDomain = new DnrDomain();
		// dnrDomain.setHandle("handle1");
		// dnrDomain.setLang("lang1");
		// dnrDomain.setLdhName("ldhName1");
		// dnrDomain.setPort43("port43");
		// indexService.saveOrUpdateIndex(dnrDomain);
		SearchCondition searchCondition = new SearchCondition("ldhName:b*");
		SearchResult<DomainIndex> result = indexService
				.queryDomains(searchCondition);
		for (DomainIndex index : result.getResultList()) {
			System.err.println(index.getHandle());
		}
	}

	public SearchResult<DomainIndex> queryDomains(
			SearchCondition searchCondition) {
		SolrQuery solrQuery = new SolrQuery();
		// String domainTypeQuery = "docType:" + DNRDOMAIN_TYPE;
		solrQuery.setQuery(searchCondition.getSearchword());
		solrQuery.setStart(searchCondition.getStart());
		solrQuery.setRows(searchCondition.getRow());
		QueryResponse queryResponse = null;
		try {
			queryResponse = server.query(solrQuery);
		} catch (SolrServerException e) {
			e.printStackTrace();
		}
		SearchResult<DomainIndex> searchResult = new SearchResult<DomainIndex>();
		try {
			setSearchResult(searchResult, queryResponse);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return searchResult;
	}

	private void setSearchResult(SearchResult<DomainIndex> searchResult,
			QueryResponse queryResponse) {
		searchResult
				.setSearchTime((double) queryResponse.getElapsedTime() / 1000);
		searchResult.setTotalResults(queryResponse.getResults().getNumFound());
		List<DomainIndex> indexes = queryResponse
				.getBeans(DomainIndex.class);
		searchResult.setResultList(indexes);
	}

	public DomainIndexService(String url) {
		try {
			server = new CommonsHttpSolrServer(url);

		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}

	public void saveOrUpdateIndex(Domain dnrDomain) {
		try {
			server.add(getSolrInputDocument(dnrDomain));
			server.commit();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private SolrInputDocument getSolrInputDocument(Domain dnrDomain) {
		DocumentObjectBinder binder = server.getBinder();
		DomainIndex index = new DomainIndex(dnrDomain);
		SolrInputDocument doc = binder.toSolrInputDocument(index);
		return doc;
	}

}
