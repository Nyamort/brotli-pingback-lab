<?php
/**
 * Plugin Name: Lab - allow the Docker-internal attacker host
 * Description: Lab-only filter for wp_safe_remote_get(). It does NOT modify
 *              WordPress core and it does NOT weaken general SSRF protection:
 *              it allows exactly one hostname, "attacker", which only
 *              resolves on the Docker lab network.
 * Version: 1.0.0
 * License: MIT
 *
 * Why this exists:
 *   WordPress pingback uses wp_safe_remote_get(), which rejects hosts that
 *   resolve to private IP ranges (127/8, 10/8, 172.16/12, 192.168/16, ...).
 *   The lab's payload server is a Docker service named "attacker" with a
 *   private address, so the stock filter would refuse it.
 *
 *   In tunnel mode the payload URL is https://<random>.trycloudflare.com,
 *   which resolves to public Cloudflare addresses. This file is then inert
 *   and can be removed entirely.
 *
 *   This is a lab harness, not a production mu-plugin.
 */

add_filter(
	'http_request_host_is_external',
	static function ( $external, $host, $url ) {
		if ( 'attacker' === strtolower( (string) $host ) ) {
			return true;
		}
		return $external;
	},
	10,
	3
);
