package com.packetanalyzer.dpi;


public final class DpiTypes {

    private DpiTypes() {}

    public static String appTypeToString(AppType type) {
        switch (type) {
            case UNKNOWN:    return "Unknown";
            case HTTP:       return "HTTP";
            case HTTPS:      return "HTTPS";
            case DNS:        return "DNS";
            case TLS:        return "TLS";
            case QUIC:       return "QUIC";
            case GOOGLE:     return "Google";
            case FACEBOOK:   return "Facebook";
            case YOUTUBE:    return "YouTube";
            case TWITTER:    return "Twitter/X";
            case INSTAGRAM:  return "Instagram";
            case NETFLIX:    return "Netflix";
            case AMAZON:     return "Amazon";
            case MICROSOFT:  return "Microsoft";
            case APPLE:      return "Apple";
            case WHATSAPP:   return "WhatsApp";
            case TELEGRAM:   return "Telegram";
            case TIKTOK:     return "TikTok";
            case SPOTIFY:    return "Spotify";
            case ZOOM:       return "Zoom";
            case DISCORD:    return "Discord";
            case GITHUB:     return "GitHub";
            case CLOUDFLARE: return "Cloudflare";
            default:         return "Unknown";
        }
    }

    /**
     * True if {@code host} IS {@code domain}, or is a subdomain of it
     * (host.equals(domain) || host.endsWith("." + domain)).
     *
     * Used for short/generic domains (e.g. "x.com", "t.co") where a plain
     * substring check would false-positive on unrelated hosts that merely
     * happen to contain those characters (e.g. "netflix.com" contains
     * "x.com", "microsoft.com" contains "t.co").
     */
    private static boolean isDomain(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain);
    }

    // Map SNI/domain to application type
    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) return AppType.UNKNOWN;

        String lower = sni.toLowerCase();

        if (lower.contains("google") || lower.contains("gstatic") ||
                lower.contains("googleapis") || lower.contains("ggpht") ||
                lower.contains("gvt1")) {
            return AppType.GOOGLE;
        }

        if (lower.contains("youtube") || lower.contains("ytimg") ||
                lower.contains("youtu.be") || lower.contains("yt3.ggpht")) {
            return AppType.YOUTUBE;
        }

        if (lower.contains("facebook") || lower.contains("fbcdn") ||
                lower.contains("fb.com") || lower.contains("fbsbx") ||
                lower.contains("meta.com")) {
            return AppType.FACEBOOK;
        }

        if (lower.contains("instagram") || lower.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }

        if (lower.contains("whatsapp") || lower.contains("wa.me")) {
            return AppType.WHATSAPP;
        }

        if (lower.contains("twitter") || lower.contains("twimg") ||
                isDomain(lower, "x.com") || isDomain(lower, "t.co")) {
            return AppType.TWITTER;
        }

        if (lower.contains("netflix") || lower.contains("nflxvideo") ||
                lower.contains("nflximg")) {
            return AppType.NETFLIX;
        }

        if (lower.contains("amazon") || lower.contains("amazonaws") ||
                lower.contains("cloudfront") || lower.contains("aws")) {
            return AppType.AMAZON;
        }

        if (lower.contains("microsoft") || lower.contains("msn.com") ||
                lower.contains("office") || lower.contains("azure") ||
                lower.contains("live.com") || lower.contains("outlook") ||
                lower.contains("bing")) {
            return AppType.MICROSOFT;
        }

        if (lower.contains("apple") || lower.contains("icloud") ||
                lower.contains("mzstatic") || lower.contains("itunes")) {
            return AppType.APPLE;
        }

        if (lower.contains("telegram") || lower.contains("t.me")) {
            return AppType.TELEGRAM;
        }

        if (lower.contains("tiktok") || lower.contains("tiktokcdn") ||
                lower.contains("musical.ly") || lower.contains("bytedance")) {
            return AppType.TIKTOK;
        }

        if (lower.contains("spotify") || lower.contains("scdn.co")) {
            return AppType.SPOTIFY;
        }

        if (lower.contains("zoom")) {
            return AppType.ZOOM;
        }

        if (lower.contains("discord") || lower.contains("discordapp")) {
            return AppType.DISCORD;
        }

        if (lower.contains("github") || lower.contains("githubusercontent")) {
            return AppType.GITHUB;
        }

        if (lower.contains("cloudflare") || lower.contains("cf-")) {
            return AppType.CLOUDFLARE;
        }

        // If SNI is present but not recognized, still mark as TLS/HTTPS
        return AppType.HTTPS;
    }
}