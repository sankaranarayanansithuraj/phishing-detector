import shap
import pickle
import numpy as np

def get_explanation(text_cleaned, top_n=10):
    try:
        with open('models/phishing_model.pkl', 'rb') as f:
            model = pickle.load(f)
        with open('models/vectorizer.pkl', 'rb') as f:
            vectorizer = pickle.load(f)

        vec           = vectorizer.transform([text_cleaned])
        feature_names = vectorizer.get_feature_names_out()

        explainer   = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(vec)

        # Index 1 = phishing class
        shap_for_phishing = shap_values[1][0]
        feature_vec       = vec.toarray()[0]

        # Only show words that actually appeared in this message
        active_indices = np.where(feature_vec > 0)[0]
        contributions  = [
            (feature_names[i], float(shap_for_phishing[i]))
            for i in active_indices
        ]

        # Sort by absolute impact, highest first
        contributions.sort(key=lambda x: abs(x[1]), reverse=True)
        return contributions[:top_n]

    except Exception as e:
        print(f"Explainer error: {e}")
        return []