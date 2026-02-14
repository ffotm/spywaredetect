import pandas as pd
import numpy as np
import pickle
import os
import gzip
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pefile
import warnings
warnings.filterwarnings('ignore')

class PEAnalysisMLModel:
    """
    Machine Learning model for PE file analysis based on MalwareData dataset
    Optimized for speed and accuracy
    """

    def __init__(self, model_path='pe_malware_model.pkl'):
        self.model = None
        self.feature_names = None
        self.is_trained = False
        self.model_path = model_path
        
        # Core features from MalwareData dataset
        self.original_feature_names = [
            'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
            'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
            'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment',
            'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
            'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion',
            'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics',
            'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit',
            'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy',
            'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize', 'SectionsMinRawsize',
            'SectionsMaxRawsize', 'SectionsMeanVirtualsize', 'SectionsMinVirtualsize',
            'SectionsMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal',
            'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy',
            'ResourcesMaxEntropy', 'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize',
            'LoadConfigurationSize', 'VersionInformationSize'
        ]
        
        # Most important features based on typical malware characteristics
        self.important_features = [
            'SectionsMeanEntropy', 'SectionsMaxEntropy', 'SectionsMinEntropy',
            'ImportsNbDLL', 'ImportsNb', 'ResourcesMeanEntropy',
            'SizeOfCode', 'SizeOfImage', 'DllCharacteristics',
            'AddressOfEntryPoint', 'SectionsNb'
        ]
        
        self.load_model()
    
    def load_model(self):
        """Load trained model from disk"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    self.model = model_data['model']
                    self.feature_names = model_data.get('features', self.original_feature_names)
                self.is_trained = True
                print(f"Loaded PE analysis ML model from {self.model_path}")
                return True
            except Exception as e:
                print(f"Error loading ML model: {e}")
                return False
        return False
    
    def save_model(self):
        """Save trained model to disk"""
        try:
            model_data = {
                'model': self.model,
                'features': self.feature_names
            }
            with open(self.model_path, 'wb') as f:
                pickle.dump(model_data, f)
            print(f"Model saved to {self.model_path}")
            return True
        except Exception as e:
            print(f"Error saving model: {e}")
            return False
    
    def train(self, csv_path='MalwareData.csv', test_size=0.2, random_state=42):
        """
        Train the model using MalwareData dataset
        Dataset format: First 41323 samples are legitimate, rest are malware
        """
        try:
            # Try to load gzipped version first
            if os.path.exists(csv_path + '.gz'):
                csv_path = csv_path + '.gz'
                print(f"Reading compressed dataset from {csv_path}")
                with gzip.open(csv_path, 'rt') as f:
                    df = pd.read_csv(f, sep='|')
            elif os.path.exists(csv_path):
                print(f"Reading dataset from {csv_path}")
                df = pd.read_csv(csv_path, sep='|')
            else:
                print(f"Dataset not found at {csv_path}")
                return None
            
            print(f"Dataset loaded: {df.shape[0]} samples, {df.shape[1]} features")
            
            # Drop non-feature columns
            X = df.drop(['Name', 'md5', 'legitimate'], axis=1, errors='ignore')
            y = df['legitimate'].values
            
            # Handle missing values
            X = X.fillna(0)
            
            # Verify feature columns
            self.feature_names = X.columns.tolist()
            
            legit_count = sum(y == 1)
            malware_count = sum(y == 0)
            print(f"Legitimate: {legit_count}, Malware: {malware_count}")
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
            
            print("Training Random Forest model...")
            # Optimized Random Forest parameters
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_split=10,
                min_samples_leaf=5,
                max_features='sqrt',
                random_state=random_state,
                n_jobs=-1,
                class_weight='balanced'  # Handle imbalanced data
            )
            
            self.model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test)
            y_proba = self.model.predict_proba(X_test)
            
            # Metrics
            accuracy = self.model.score(X_test, y_test)
            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = cm.ravel()
            
            fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0
            fnr = (fn / (fn + tp)) * 100 if (fn + tp) > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            metrics = {
                'accuracy': accuracy * 100,
                'false_positive_rate': fpr,
                'false_negative_rate': fnr,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'confusion_matrix': cm.tolist(),
                'n_features': len(self.feature_names),
                'n_train': len(X_train),
                'n_test': len(X_test)
            }
            
            print(f"\nTraining complete!")
            print(f"Accuracy: {metrics['accuracy']:.2f}%")
            print(f"Precision: {metrics['precision']:.3f}")
            print(f"Recall: {metrics['recall']:.3f}")
            print(f"F1 Score: {metrics['f1_score']:.3f}")
            print(f"False Positive Rate: {metrics['false_positive_rate']:.2f}%")
            print(f"False Negative Rate: {metrics['false_negative_rate']:.2f}%")
            
            # Feature importance
            feature_importance = sorted(
                zip(self.feature_names, self.model.feature_importances_),
                key=lambda x: x[1],
                reverse=True
            )
            print("\nTop 10 Important Features:")
            for feat, importance in feature_importance[:10]:
                print(f"  {feat}: {importance:.4f}")
            
            self.is_trained = True
            self.save_model()
            
            return metrics
            
        except Exception as e:
            print(f"Error training model: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def extract_pe_features(self, filepath):
        """Extract PE features from a file"""
        try:
            pe = pefile.PE(filepath)
            
            features = {}
            for name in self.original_feature_names:
                features[name] = 0
            
            # Basic PE headers
            features['Machine'] = pe.FILE_HEADER.Machine
            features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
            features['Characteristics'] = pe.FILE_HEADER.Characteristics
            features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
            features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
            features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
            features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
            features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
            features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
            features['BaseOfData'] = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
            features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
            features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
            features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            features['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
            features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
            features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
            features['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
            features['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
            features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
            features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
            features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
            features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
            features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
            features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
            features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
            features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
            features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
            features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            
            # Section information
            sections = pe.sections
            features['SectionsNb'] = len(sections)
            
            if sections:
                entropies = [self._calculate_section_entropy(s) for s in sections]
                features['SectionsMeanEntropy'] = np.mean(entropies)
                features['SectionsMinEntropy'] = np.min(entropies)
                features['SectionsMaxEntropy'] = np.max(entropies)
                
                raw_sizes = [s.SizeOfRawData for s in sections]
                features['SectionsMeanRawsize'] = np.mean(raw_sizes) if raw_sizes else 0
                features['SectionsMinRawsize'] = np.min(raw_sizes) if raw_sizes else 0
                features['SectionsMaxRawsize'] = np.max(raw_sizes) if raw_sizes else 0
                
                virtual_sizes = [s.Misc_VirtualSize for s in sections]
                features['SectionsMeanVirtualsize'] = np.mean(virtual_sizes) if virtual_sizes else 0
                features['SectionsMinVirtualsize'] = np.min(virtual_sizes) if virtual_sizes else 0
                features['SectionsMaxVirtualsize'] = np.max(virtual_sizes) if virtual_sizes else 0
            
            # Import information
            features['ImportsNbDLL'] = 0
            features['ImportsNb'] = 0
            features['ImportsNbOrdinal'] = 0
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                features['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    features['ImportsNb'] += len(entry.imports)
                    features['ImportsNbOrdinal'] += sum(1 for imp in entry.imports if imp.ordinal)
            
            # Export information
            features['ExportNb'] = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if pe.DIRECTORY_ENTRY_EXPORT.symbols else 0
            
            # Resource information
            features['ResourcesNb'] = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resources = []
                self._count_resources(pe.DIRECTORY_ENTRY_RESOURCE.entries, resources)
                features['ResourcesNb'] = len(resources)
            
            # Convert to array
            feature_vector = np.array([features[name] for name in self.feature_names])
            
            return feature_vector.reshape(1, -1)
            
        except Exception as e:
            return None
    
    def _calculate_section_entropy(self, section):
        """Calculate entropy for a PE section"""
        try:
            data = section.get_data()
            if not data:
                return 0
            
            byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
            byte_counts = byte_counts[byte_counts > 0]
            
            probs = byte_counts / len(data)
            entropy = -np.sum(probs * np.log2(probs))
            
            return entropy
        except:
            return 0
    
    def _count_resources(self, entries, resources):
        """Recursively count resources"""
        for entry in entries:
            if hasattr(entry, 'directory'):
                self._count_resources(entry.directory.entries, resources)
            else:
                resources.append(entry)
    
    def predict(self, filepath):
        """
        Predict if a file is malware
        Returns: (is_malware, confidence, feature_importance)
        """
        if not self.is_trained or self.model is None:
            return False, 0.0, None
        
        try:
            features = self.extract_pe_features(filepath)
            if features is None:
                return False, 0.0, None
            
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            # probabilities[0] = legitimate, probabilities[1] = malware
            # In dataset: 0 = malware, 1 = legitimate
            is_malware = prediction == 0
            malware_probability = probabilities[0] if is_malware else (1 - probabilities[1])
            
            feature_importance = None
            if hasattr(self.model, 'feature_importances_'):
                feature_importance = dict(zip(self.feature_names, self.model.feature_importances_))
            
            return is_malware, malware_probability, feature_importance
            
        except Exception as e:
            return False, 0.0, None
    
    def get_model_info(self):
        """Get model information"""
        if not self.is_trained:
            return {"status": "not_trained"}
        
        return {
            "status": "trained",
            "n_features": len(self.feature_names) if self.feature_names else 0,
            "model_type": type(self.model).__name__ if self.model else None,
            "feature_names": self.feature_names
        }


def train_pe_model(csv_path='MalwareData.csv'):
    """Train the PE analysis model"""
    print("=" * 60)
    print("PE Malware Detection Model Training")
    print("=" * 60)
    
    model = PEAnalysisMLModel()
    metrics = model.train(csv_path)
    
    if metrics:
        print("\n" + "=" * 60)
        print("Training Successful!")
        print("=" * 60)
        print(f"Accuracy: {metrics['accuracy']:.2f}%")
        print(f"Precision: {metrics['precision']:.3f}")
        print(f"Recall: {metrics['recall']:.3f}")
        print(f"F1 Score: {metrics['f1_score']:.3f}")
        print(f"False Positive Rate: {metrics['false_positive_rate']:.2f}%")
        print(f"False Negative Rate: {metrics['false_negative_rate']:.2f}%")
        print("=" * 60)
    else:
        print("\nTraining failed!")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Train PE Malware Detection Model')
    parser.add_argument('--csv', type=str, default='MalwareData.csv',
                        help='Path to MalwareData.csv (will auto-detect .gz)')
    
    args = parser.parse_args()
    
    train_pe_model(args.csv)