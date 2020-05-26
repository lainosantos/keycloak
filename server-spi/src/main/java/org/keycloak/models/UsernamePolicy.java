/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.models;

import org.keycloak.policy.UsernamePolicyConfigException;
import org.keycloak.policy.UsernamePolicyProvider;

import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class UsernamePolicy implements Serializable {
    public static final String REGEX_PATTERN_ID = "regexPattern";

    private Map<String, Object> policyConfig;
    private Builder builder;

    public static UsernamePolicy empty() {
        return new UsernamePolicy(null, new HashMap<>());
    }

    public static Builder build() {
        return new Builder();
    }

    public static UsernamePolicy parse(KeycloakSession session, String policyString) {
        return new Builder(policyString).build(session);
    }

    private UsernamePolicy(Builder builder, Map<String, Object> policyConfig) {
        this.builder = builder;
        this.policyConfig = policyConfig;
    }

    public Set<String> getPolicies() {
        return policyConfig.keySet();
    }

    public <T> T getPolicyConfig(String key) {
        return (T) policyConfig.get(key);
    }

    @Override
    public String toString() {
        return builder.asString();
    }

    public Builder toBuilder() {
        return builder.clone();
    }

    public static class Builder {

        private LinkedHashMap<String, String> map;

        private Builder() {
            this.map = new LinkedHashMap<>();
        }

        private Builder(LinkedHashMap<String, String> map) {
            this.map = map;
        }

        private Builder(String policyString) {
            map = new LinkedHashMap<>();

            if (policyString != null && !policyString.trim().isEmpty()) {
                for (String policy : policyString.split(" and ")) {
                    policy = policy.trim();

                    String key;
                    String config = null;

                    int i = policy.indexOf('(');
                    if (i == -1) {
                        key = policy.trim();
                    } else {
                        key = policy.substring(0, i).trim();
                        config = policy.substring(i + 1, policy.length() - 1);
                    }

                    map.put(key, config);
                }
            }
        }

        public boolean contains(String key) {
            return map.containsKey(key);
        }

        public String get(String key) {
            return map.get(key);
        }

        public Builder put(String key, String value) {
            map.put(key, value);
            return this;
        }

        public Builder remove(String key) {
            map.remove(key);
            return this;
        }

        public UsernamePolicy build(KeycloakSession session) {
            Map<String, Object> config = new HashMap<>();
            for (Map.Entry<String, String> e : map.entrySet()) {

                UsernamePolicyProvider provider = session.getProvider(UsernamePolicyProvider.class, e.getKey());
                if (provider == null) {
                    throw new UsernamePolicyConfigException("Username policy not found");
                }

                Object o;
                try {
                    o = provider.parseConfig(e.getValue());
                } catch (UsernamePolicyConfigException ex) {
                    throw new ModelException("Invalid config for " + e.getKey() + ": " + ex.getMessage());
                }

                config.put(e.getKey(), o);
            }
            return new UsernamePolicy(this, config);
        }

        public String asString() {
            if (map.isEmpty()) {
                return null;
            }

            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Map.Entry<String, String> e : map.entrySet()) {
                if (first) {
                    first = false;
                } else {
                    sb.append(" and ");
                }

                sb.append(e.getKey());

                String c = e.getValue();
                if (c != null && !c.trim().isEmpty()) {
                    sb.append("(");
                    sb.append(c);
                    sb.append(")");
                }
            }
            return sb.toString();
        }

        public Builder clone() {
            return new Builder((LinkedHashMap<String, String>) map.clone());
        }

    }

}
