use async_trait::async_trait;
use error_stack::ResultExt;
use mea::mpsc::UnboundedSender;
use serde::{Deserialize, Serialize};

use crate::{
    AppResult,
    domain::models::vuln_information::{CreateVulnInformation, Severity},
    errors::Error,
    output::plugins::vuln::{VulnPlugin, register_plugin},
    utils::{http_client::HttpClient, util::timestamp_to_datetime},
};

const WIZ_URL: &str = "https://hdr4182jve-dsn.algolia.net/1/indexes/*/queries?x-algolia-agent=Algolia%20for%20JavaScript%20(5.35.0)%3B%20Search%20(5.35.0)%3B%20Browser%3B%20instantsearch.js%20(4.79.2)%3B%20react%20(19.2.1)%3B%20react-instantsearch%20(7.16.2)%3B%20react-instantsearch-core%20(7.16.2)%3B%20next.js%20(15.5.7)%3B%20JS%20Helper%20(3.26.0)&x-algolia-api-key=2023c7fbf68076909d1a85ec42cea550&x-algolia-application-id=HDR4182JVE";
const WIZ_PAGE_SIZE: i32 = 10;

// 定义数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizRequest {
    pub requests: Vec<WizQueryRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WizQueryRequest {
    pub index_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facet_filters: Option<Vec<Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facets: Option<Vec<String>>,
    pub highlight_post_tag: String,
    pub highlight_pre_tag: String,
    pub hits_per_page: i32,
    pub max_values_per_facet: i32,
    pub page: i32,
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analytics: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub click_analytics: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WizResponse {
    pub results: Vec<WizResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WizResult {
    pub hits: Vec<WizHit>,
    pub nb_hits: i64,
    pub page: i32,
    pub nb_pages: i32,
    pub hits_per_page: i32,
    #[serde(rename = "processingTimeMS")]
    pub processing_time_ms: i32,
    pub query: String,
    pub params: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WizHit {
    pub id: String,
    pub external_id: Option<String>,
    pub name: String,
    pub description: String,
    pub source_url: Option<String>,
    pub affected_software: Option<Vec<String>>,
    pub affected_technologies: Option<Vec<AffectedTechnology>>,
    pub severity: String,
    pub exploitable: Option<bool>,
    pub source_feeds: Option<Vec<SourceFeed>>,
    pub published_at: Option<i64>,
    pub epss_percentile: Option<f64>,
    pub epss_probability: Option<f64>,
    pub base_score: Option<f64>,
    pub cvss2: Option<Cvss>,
    pub cvss3: Option<Cvss>,
    pub is_high_profile_threat: Option<bool>,
    pub has_cisa_kev_exploit: Option<bool>,
    pub ai_description: Option<AiDescription>,
    pub index: Option<bool>,
    pub has_fix: Option<bool>,
    pub has_more_than_50_affected_software: Option<bool>,
    pub batch_id: Option<String>,
    #[serde(rename = "objectID")]
    pub object_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AffectedTechnology {
    pub id: String,
    pub name: String,
    pub icon: Option<String>,
    pub description: Option<String>,
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceFeed {
    pub name: String,
    pub id: String,
    pub url: Option<String>,
    pub icon: Option<String>,
    pub affected_platforms: Option<Vec<AffectedPlatform>>,
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AffectedPlatform {
    pub added_at: Option<String>,
    pub advisory_url: Option<String>,
    pub affected_versions: Option<Vec<String>>,
    pub has_fix: Option<bool>,
    pub id: String,
    pub name: String,
    pub severity: Option<String>,
    pub technology: Option<Technology>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Technology {
    pub id: String,
    pub name: String,
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cvss {
    pub attack_complexity: Option<String>,
    pub attack_vector: Option<String>,
    pub confidentiality_impact: Option<String>,
    pub integrity_impact: Option<String>,
    pub privileges_required: Option<bool>,
    pub user_interaction_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiDescription {
    pub overview: Option<String>,
    pub technical_details: Option<String>,
    pub impact: Option<String>,
    pub exploitability: Option<String>,
    pub mitigation_and_workarounds: Option<String>,
    pub community_reactions: Option<String>,
    pub additional_resources: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WizPlugin {
    name: String,
    display_name: String,
    link: String,
    http_client: HttpClient,
    sender: UnboundedSender<CreateVulnInformation>,
}

#[async_trait]
impl VulnPlugin for WizPlugin {
    fn get_name(&self) -> String {
        self.name.to_string()
    }

    fn get_display_name(&self) -> String {
        self.display_name.to_string()
    }

    fn get_link(&self) -> String {
        self.link.to_string()
    }

    async fn update(&self, page_limit: i32) -> AppResult<()> {
        let mut page_count = self.get_page_count().await?;
        if page_count > page_limit {
            page_count = page_limit;
        }

        for page in 0..page_count {
            let wiz_resp = self.get_wiz_data(page).await?;
            if let Some(hits) = wiz_resp.results.first().map(|r| r.hits.clone()) {
                for hit in hits {
                    let vuln_info = self.parse_hit(hit).await;
                    match vuln_info {
                        Ok(data) => {
                            self.sender.send(data).change_context_lazy(|| {
                                Error::Message(
                                    "Failed to send vuln information to channel".to_string(),
                                )
                            })?;
                        }
                        Err(err) => log::error!("parsing wiz hit error: {}", err),
                    }
                }
            }
        }
        Ok(())
    }
}

impl WizPlugin {
    pub fn try_new(sender: UnboundedSender<CreateVulnInformation>) -> AppResult<WizPlugin> {
        let http_client = HttpClient::try_new()?;
        let wiz = WizPlugin {
            name: "WizPlugin".to_string(),
            display_name: "Wiz漏洞库".to_string(),
            link: "https://www.wiz.io".to_string(),
            http_client,
            sender,
        };
        register_plugin(wiz.name.clone(), Box::new(wiz.clone()));
        Ok(wiz)
    }

    pub async fn get_wiz_data(&self, page: i32) -> AppResult<WizResponse> {
        let request_body = WizRequest {
            requests: vec![
                WizQueryRequest {
                    index_name: "cve-db".to_string(),
                    facet_filters: Some(vec![vec!["isHighProfileThreat:true".to_string()]]),
                    facets: Some(vec![
                        "affectedTechnologies.filter".to_string(),
                        "exploitable".to_string(),
                        "hasCisaKevExploit".to_string(),
                        "hasFix".to_string(),
                        "isHighProfileThreat".to_string(),
                        "publishedAt".to_string(),
                        "severity".to_string(),
                        "sourceFeeds.filter".to_string(),
                    ]),
                    highlight_post_tag: "__/ais-highlight__".to_string(),
                    highlight_pre_tag: "__ais-highlight__".to_string(),
                    hits_per_page: WIZ_PAGE_SIZE,
                    max_values_per_facet: 200,
                    page,
                    query: "".to_string(),
                    analytics: None,
                    click_analytics: None,
                },
                WizQueryRequest {
                    index_name: "cve-db".to_string(),
                    facet_filters: None,
                    facets: Some(vec!["isHighProfileThreat".to_string()]),
                    highlight_post_tag: "__/ais-highlight__".to_string(),
                    highlight_pre_tag: "__ais-highlight__".to_string(),
                    hits_per_page: 10,
                    max_values_per_facet: 200,
                    page: 0,
                    query: "".to_string(),
                    analytics: Some(false),
                    click_analytics: Some(false),
                },
            ],
        };

        let response = self.http_client.post_json(WIZ_URL, &request_body).await?;

        let response_text = response
            .text()
            .await
            .map_err(|e| Error::Message(format!("Failed to get response text: {}", e)))?;

        let wiz_resp: WizResponse = serde_json::from_str(&response_text)
            .map_err(|e| Error::Message(format!("Failed to parse Wiz response: {}", e)))?;

        Ok(wiz_resp)
    }

    pub async fn get_page_count(&self) -> AppResult<i32> {
        let wiz_resp = self.get_wiz_data(0).await?;
        if let Some(result) = wiz_resp.results.first() {
            let total_hits = result.nb_hits;
            let page_count = (total_hits + WIZ_PAGE_SIZE as i64 - 1) / WIZ_PAGE_SIZE as i64;
            Ok(page_count as i32)
        } else {
            Err(Error::Message("Failed to get page count from Wiz response".to_string()).into())
        }
    }

    pub async fn parse_hit(&self, hit: WizHit) -> AppResult<CreateVulnInformation> {
        let key = hit.object_id.clone();
        let title = hit.name.clone();
        let description = hit.description.clone();
        let severity = self.get_severity(&hit.severity);
        let cve = hit.external_id.clone().unwrap_or_default();
        let disclosure = if let Some(timestamp) = hit.published_at {
            timestamp_to_datetime(timestamp).unwrap_or_default()
        } else {
            String::new()
        };

        let mut tags = Vec::new();
        if let Some(is_high_profile_threat) = hit.is_high_profile_threat
            && is_high_profile_threat
        {
            tags.push("高危威胁".to_string());
        }
        if let Some(exploitable) = hit.exploitable
            && exploitable
        {
            tags.push("可利用".to_string());
        }
        if let Some(has_cisa_kev_exploit) = hit.has_cisa_kev_exploit
            && has_cisa_kev_exploit
        {
            tags.push("CISA KEV".to_string());
        }
        if let Some(has_fix) = hit.has_fix
            && has_fix
        {
            tags.push("有修复".to_string());
        }

        let detail_link = format!("https://www.wiz.io/vulnerability-database/cve/{}", title);

        let data = CreateVulnInformation {
            key,
            title,
            description,
            severity: severity.to_string(),
            cve,
            disclosure: disclosure.to_string(),
            reference_links: Vec::new(),
            solutions: "".to_string(),
            source: self.link.clone(),
            source_name: self.name.to_string(),
            tags,
            reasons: Vec::new(),
            github_search: Vec::new(),
            pushed: false,
            detail_link,
        };
        Ok(data)
    }

    fn get_severity(&self, severity_str: &str) -> Severity {
        match severity_str.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Low,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mea::mpsc::unbounded;

    #[tokio::test]
    async fn test_parse_hit() {
        // 创建一个测试用的通道
        let (sender, _receiver) = unbounded::<CreateVulnInformation>();

        // 创建 WizPlugin 实例
        let plugin = WizPlugin::try_new(sender).expect("Failed to create WizPlugin");

        // 获取第一页数据
        let response = plugin
            .get_wiz_data(0)
            .await
            .expect("Failed to get Wiz data");

        // 解析第一个 hit
        if let Some(first_result) = response.results.first() {
            if let Some(first_hit) = first_result.hits.first() {
                let result = plugin.parse_hit(first_hit.clone()).await;

                match result {
                    Ok(vuln_info) => {
                        // 验证解析结果
                        assert!(!vuln_info.key.is_empty(), "Vuln info should have a key");
                        assert!(
                            !vuln_info.source.is_empty(),
                            "Vuln info should have a source"
                        );
                        assert!(
                            !vuln_info.source_name.is_empty(),
                            "Vuln info should have a source name"
                        );

                        // 打印一些信息用于调试
                        println!("Successfully parsed hit:");
                        println!("  Key: {}", vuln_info.key);
                        println!("  Title: {}", vuln_info.title);
                        println!("  Severity: {}", vuln_info.severity);
                        println!("  CVE: {}", vuln_info.cve);
                        println!("  Tags: {:?}", vuln_info.tags);
                        println!("  Disclosure: {}", vuln_info.disclosure);
                    }
                    Err(e) => {
                        panic!("Failed to parse hit: {:?}", e);
                    }
                }
            } else {
                panic!("No hits found in the response");
            }
        } else {
            panic!("No results found in the response");
        }
    }
}
